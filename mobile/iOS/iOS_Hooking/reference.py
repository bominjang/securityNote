# -*- conding: utf-8 -*-
import frida
import sys 
 
PACKAGE_NAME = "kr.history"
 
#send실행 시 출력할 format정의
def on_message(message, data):
    try:
        if message:
            print("[JSBACH] {0}".format(message["payload"]))
    except Exception as e:
        print(message)
        print(e)
 
 
def do_hook():
 
    hook = """ 
    //Objective-C가 실행 가능한 환경인지 검사
    if(ObjC.available){
        //해당 attach된 프로세스의 메모리에 올라가있는 클래스들을 가져올 수있고,
        //아래 for문은 타겟 클래스가 존재하는지 검사했다.
        for(var className in ObjC.classes){
            if(className == "Game2ViewController"){
                send("Found our target class : " + className);
            }
        }
    
        //Hooking을 진행할 메서드 객체를 가져온다.
        var hook_method = ObjC.classes.Game2ViewController["- recognizeAnswer"];
        send("print hook_method : " + hook_method);
        
        Interceptor.attach(hook_method.implementation, {
        
            //onEnter는 후킹함수 진입 시 실행되며, args[0]에는 self객체가
            //args[1]에는 selector객체가 들어있어 접근 가능하며
            //args[2]에는 해당 함수의 매개변수들이 들어있다.
            //매개변수를 변경하고 싶다면 이곳에서 변경한다.
            onEnter: function(args){
                
                var receiver = new ObjC.Object(args[0]);
                send("Target class : " + receiver.$className);
                send("Target superclass : " + receiver.$superClass.$className);
                var sel = ObjC.selectorAsString(args[1]);
                send("typeof sel = " + typeof sel);
                send("Hooked the target method : " + sel);
            },
            //onLeave는 함수 종료전 처리를 할 수 있다.
            //retVal에는 원래의 return값이 들어있고, return값을 변경하고 싶다면
            //이곳에서 변경한다.
            onLeave: function(retVal){
                //오답 시 리턴 값
                var wrong   = -1;
                //정답 시 리턴 값
                var correct = 1; 
                //retVal은 Object객체이며, int값으로 사용하기 위해 toInt32()를 사용
                var orig_rtn = retVal.toInt32();
                if(-1 == orig_rtn){
                    send("answer is Wrong!! : " + orig_rtn);
                    send("answer is replaced!!");
                    //값을 변경하기위해 replace()를 사용하여 변경함
                    retVal.replace(correct);
                }
                else{
                    send("answer is Correct!! : " + orig_rtn);
                }
            }
        });
    }
    //Objective-C 실행 환경이 아닌 경우 로그 출력
    else{
        console.log("Objective-C Runtime is not available!");
    }
    """
 
    return hook
 
if __name__ == '__main__':
 
    try:
        #연결할 단말을 찾는다.
        device = frida.get_device_manager().enumerate_devices()[-1]
 
        #타겟으로 할 앱의 패키지명으로 단말에서 실행되고 있는 pid를 가져온다.
        pid = device.spawn([PACKAGE_NAME])
        print("[JSBACH] {} is starting. (pid : {})".format(PACKAGE_NAME, pid))
 
        #위에서 얻어온 pid에 attach한다.
        session = device.attach(pid)
        device.resume(pid)
 
        #후킹코드를 injection한다.
        script = session.create_script(do_hook())
        script.on('message', on_message)
        script.load()
        sys.stdin.read()
    except KeyboardInterrupt:
        sys.exit(0)
