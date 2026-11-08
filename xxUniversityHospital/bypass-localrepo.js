// bypass-localrepo.js
Java.perform(function(){
  // 루팅 체크 우회 유지
  try { var ROJ=Java.use("com.lemonhc.mcare.new_framework.util.RealizationOfJustice");
    ROJ.isRooting.overloads.forEach(function(ov){ov.implementation=function(){return;};});
    console.log("[+] isRooting 우회"); }catch(e){}
  var S=Java.use("java.lang.System");S.exit.implementation=function(c){console.log("[BLOCK] exit");};
  var P=Java.use("android.os.Process");P.killProcess.implementation=function(p){console.log("[BLOCK] kill");};

  var Success = Java.use("com.lemonhc.mcare.domain.model.result.AppIronResult$Success");

  // 구현체 startAppIron 후킹
  try {
    var Impl = Java.use("com.lemonhc.mcare.data.repository.LocalRepositoryImpl");
    // 메소드 시그니처 확인
    Impl.startAppIron.overloads.forEach(function(ov, idx){
      console.log("[SIG] startAppIron overload "+idx+": "+ov.argumentTypes.map(function(t){return t.className;}).join(", "));
      ov.implementation = function(cont){
        console.log("[FORCE] LocalRepositoryImpl.startAppIron → Success");
        // suspend 함수: Continuation에 Success를 넘기거나, Success 직접 리턴
        return Success.INSTANCE;
      };
    });
    console.log("[+] LocalRepositoryImpl.startAppIron 후킹 완료");
  } catch(e){ console.log("[!] "+e); }

  console.log("[*] bypass-localrepo 설치");
});
// 네이티브 종료 차단
var iv=setInterval(function(){var b=Module.findBaseAddress("libAppIron-jni_v2.13.28.so");
  if(b){clearInterval(iv);["_exit","exit","abort"].forEach(function(n){var p=Module.findExportByName("libc.so",n);
    if(p){try{Interceptor.replace(p,new NativeCallback(function(c){},'void',['int']));}catch(e){}}});}},10);