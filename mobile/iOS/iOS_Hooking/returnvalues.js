if(ObjC.available){
    try{
        var classname = "JailbreakDetectionVC";
        var funcName = "- isJailbroken";
        var hook = eval('ObjC.classes.'+classname+'["'+funcName+'"]');
        //method나타낼 때, class명[method명]으로 나타냄
        Interceptor.attach(hook.implementation,{
            onLeave: function(retval){
            console.log("[*] Class Name: "+classname);
            console.log("[*] Method Name: "+ funcName);
            console.log("\t[-] Type of return value: "+typeof retval);
            console.log("\t[-] Return Value: "+retval);
            var newretval = ptr("0x0");
            retval.replace(newretval);
            console.log("\t[-] New Return Value : "+newretval);
        }
        });
    }
    catch(err){ console.log("[!] Exception2: "+err.message);
    }
}

else{
    console.log("Objective-C Runtime is not available!");
}


//Interceptor는 target functionn을 부르고 싶을 때 사용함.
//callback argument는 onEnter나 onLeave 객체를 갖고있는 요소임.
//onEnter : function(args) : callback fucntion은 args 인자 하나를 받음. 이것은
//target(NativePointer)의 인자 argument 읽기나 쓰기용으로 쓰일 수 있음.

//onLeave : function(retval) : raw return value를 포함하는 NativePointer의 파생객체인 retval을 인자로가지는 callback fucntion임.
//retval.replace(1337)을 call해서 integer 1337로 retrun value를 바꿀 수도 있고,
//retval.replace(ptr("0x1234"))를 통해 pointer 값으로도 바꿀 수 있다.
//이 객체는 onLeave에서 재활용되므로 콜백 외부에서 저장 및 사용하면 안됨.
//저장해야하면 ptr(retval.toString())을 이용하면 됨.

