/* مؤسسة الأمانة — الدخول وإدارة المستخدمين عبر الخادم (server.py)
   التحقق من كلمة المرور والصلاحيات يتم على الخادم، والمتصفح يحمل كوكي جلسة HttpOnly فقط. */
const Auth=(()=>{
  const IDLE_MS=15*60*1000;
  const ROLES={admin:'مدير',accountant:'محاسب',viewer:'مشاهدة'};
  const PERMS={admin:['write','backup','restore','users'],accountant:['write','backup'],viewer:[]};
  let me=null,users=[],cb={login:async()=>{},logout:()=>{}},idleTimer=null,lastAct=Date.now(),lastPing=0;
  const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  async function api(method,path,body){
    const opts={method,credentials:'same-origin',headers:{'X-Requested-With':'amanah'}};
    if(body!==undefined){opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body)}
    let res;try{res=await fetch(path,opts)}catch(e){return {status:0,data:{error:'تعذر الاتصال بالخادم'}}}
    let data={};try{data=await res.json()}catch(e){}
    if(res.status===401&&me&&path!=='/api/login')expired();
    return {status:res.status,data};
  }
  const current=()=>me?{...me}:null;
  const can=p=>Boolean(me&&(PERMS[me.role]||[]).includes(p));
  const fail=r=>({ok:false,msg:(r.data&&r.data.error)||'تعذر تنفيذ العملية'});

  function expired(){if(!me)return;me=null;users=[];clearInterval(idleTimer);cb.logout();showOverlay('login','انتهت الجلسة. سجّل الدخول من جديد.')}
  async function startSession(u,resumed){me=u;lastAct=Date.now();hideOverlay();watchIdle();await cb.login(u,{resumed:Boolean(resumed)})}
  function watchIdle(){clearInterval(idleTimer);idleTimer=setInterval(()=>{if(me&&Date.now()-lastAct>IDLE_MS)logout('انتهت الجلسة لعدم النشاط. سجّل الدخول من جديد.')},15000)}
  async function logout(msg){clearInterval(idleTimer);const had=me;me=null;users=[];if(had)await api('POST','/api/logout',{});cb.logout();showOverlay('login',msg)}

  async function setup(name,username,password){const r=await api('POST','/api/setup',{name,username,password});if(r.status!==200)return fail(r);await startSession(r.data.user);return {ok:true}}
  async function login(username,password){const r=await api('POST','/api/login',{username,password});if(r.status!==200)return fail(r);await startSession(r.data.user);return {ok:true}}

  /* ---- المستخدمون (للمدير) ---- */
  async function refreshUsers(){const r=await api('GET','/api/users');users=r.status===200?r.data.users:[];return users}
  const list=()=>users.slice();
  async function addUser(u){const r=await api('POST','/api/users',u);return r.status===200?{ok:true}:fail(r)}
  async function updateUser(id,p){const r=await api('PATCH','/api/users/'+encodeURIComponent(id),p);return r.status===200?{ok:true}:fail(r)}
  async function deleteUser(id){const r=await api('DELETE','/api/users/'+encodeURIComponent(id),undefined);return r.status===200?{ok:true}:fail(r)}
  async function changeOwnPassword(oldPw,newPw){const r=await api('POST','/api/password',{old:oldPw,new:newPw});return r.status===200?{ok:true}:fail(r)}

  /* ---- واجهة الدخول ---- */
  function overlay(){let el=document.getElementById('authOverlay');if(!el){el=document.createElement('div');el.id='authOverlay';el.className='auth-overlay';document.body.appendChild(el)}return el}
  function hideOverlay(){const el=document.getElementById('authOverlay');if(el)el.remove();document.body.classList.remove('locked')}
  function showOverlay(mode,msg){
    document.body.classList.add('locked');const el=overlay();const setupMode=mode==='setup';
    el.innerHTML=`<div class="auth-card"><div class="auth-brand"><img class="auth-logo" src="${typeof LOGO_DATA!=='undefined'?LOGO_DATA:'logo.png'}" alt="الأمانة"><div><div class="auth-title">مؤسسة الأمانة</div><div class="auth-sub">${setupMode?'إنشاء حساب المدير (أول تشغيل)':'تسجيل الدخول'}</div></div></div>
    ${msg?`<div class="auth-msg ${setupMode?'':'info'}">${esc(msg)}</div>`:''}
    <form id="authForm" autocomplete="on" novalidate>
      ${setupMode?'<label>الاسم</label><input id="aName" autocomplete="name" />':''}
      <label>اسم المستخدم</label><input id="aUser" autocomplete="username" dir="ltr" autocapitalize="off" />
      <label>كلمة المرور</label><input id="aPass" type="password" autocomplete="${setupMode?'new-password':'current-password'}" dir="ltr" />
      ${setupMode?'<label>تأكيد كلمة المرور</label><input id="aPass2" type="password" autocomplete="new-password" dir="ltr" />':''}
      <label class="auth-check"><input id="aShow" type="checkbox" /> إظهار كلمة المرور</label>
      <div id="authErr" class="auth-msg err" style="display:none"></div>
      <button class="btn primary auth-btn" id="aSubmit" type="submit">${setupMode?'إنشاء الحساب والدخول':'دخول'}</button>
    </form>
    <div class="auth-foot">${setupMode?'هذا الحساب هو المدير ويمكنه إضافة بقية المستخدمين لاحقًا.':'البيانات محفوظة على خادم المكتب.'}</div></div>`;
    const err=m=>{const e=el.querySelector('#authErr');e.textContent=m;e.style.display=m?'block':'none'};
    el.querySelector('#aShow').addEventListener('change',e=>{el.querySelectorAll('input[data-pw]').forEach(i=>{i.type=e.target.checked?'text':'password'})});
    el.querySelectorAll('input[type=password]').forEach(i=>{i.dataset.pw='1'});
    el.querySelector('#authForm').addEventListener('submit',async ev=>{
      ev.preventDefault();err('');const btn=el.querySelector('#aSubmit');btn.disabled=true;
      try{
        let r;
        if(setupMode){const p=el.querySelector('#aPass').value;if(p!==el.querySelector('#aPass2').value){err('تأكيد كلمة المرور غير مطابق');return}r=await setup(el.querySelector('#aName').value,el.querySelector('#aUser').value,p)}
        else r=await login(el.querySelector('#aUser').value,el.querySelector('#aPass').value);
        if(!r.ok){err(r.msg);const p=el.querySelector('#aPass');if(p){p.value='';p.focus()}}
      }finally{btn.disabled=false}
    });
    setTimeout(()=>{const f=el.querySelector(setupMode?'#aName':'#aUser');f&&f.focus()},0);
  }

  async function init(callbacks){
    cb={...cb,...callbacks};
    ['click','keydown','touchstart','mousemove'].forEach(ev=>document.addEventListener(ev,()=>{
      lastAct=Date.now();if(me&&lastAct-lastPing>60000){lastPing=lastAct;api('POST','/api/ping',{})}
    },{passive:true}));
    const r=await api('GET','/api/status');
    if(r.status===0){showOverlay('login','تعذر الاتصال بالخادم. تأكد أن server.py يعمل ثم أعد تحميل الصفحة.');return}
    if(r.data.user)await startSession(r.data.user,true);
    else showOverlay(r.data.setup?'setup':'login');
  }
  return {init,login,logout,current,can,list,refreshUsers,addUser,updateUser,deleteUser,changeOwnPassword,setup,api,ROLES};
})();
