package com.anjia.unidbgserver.service;

import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONObject;
import com.anjia.unidbgserver.config.UnidbgProperties;
import com.anjia.unidbgserver.utils.TempFileUtils;
import com.github.unidbg.*;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.memory.Memory;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.zip.InflaterInputStream;

import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.springframework.beans.propertyeditors.CustomBooleanEditor;

@Slf4j
public class TTEncryptService extends AbstractJni {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    private final DvmClass TTEncryptUtils;
    private final static String TT_ENCRYPT_LIB_PATH = "data/apks/so/libvolleydemo.so";
    private final Boolean DEBUG_FLAG;

    @SneakyThrows TTEncryptService(UnidbgProperties unidbgProperties) {
        DEBUG_FLAG = unidbgProperties.isVerbose();
        // 创建模拟器实例，要模拟32位或者64位，在这里区分
        EmulatorBuilder<AndroidEmulator> builder = AndroidEmulatorBuilder.for32Bit().setProcessName("com.qidian.dldl.official");
        // 动态引擎
        if (unidbgProperties.isDynarmic()) {
            builder.addBackendFactory(new DynarmicFactory(true));
        }
        emulator = builder.build();
        // 模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));

        // 创建Android虚拟机
        vm = emulator.createDalvikVM();
        // 设置是否打印Jni调用细节
        vm.setVerbose(unidbgProperties.isVerbose());
        // 加载libttEncrypt.so到unicorn虚拟内存，加载成功以后会默认调用init_array等函数
        DalvikModule dm = vm.loadLibrary(TempFileUtils.getTempFile(TT_ENCRYPT_LIB_PATH), false);
        // 手动执行JNI_OnLoad函数
        dm.callJNI_OnLoad(emulator);
        // 加载好的libttEncrypt.so对应为一个模块
        module = dm.getModule();

        dm.callJNI_OnLoad(emulator);

        vm.setJni(this);

        //TTEncryptUtils = vm.resolveClass("com/bytedance/frameworks/core/encrypt/TTEncryptUtils");
        //Java_com_android_awsomedemo_DemoTool_socialELux
        TTEncryptUtils = vm.resolveClass("com/android/awsomedemo/DemoTool");
    }

    public void destroy() throws IOException {
        emulator.close();
        if (DEBUG_FLAG) {
            log.info("destroy");
        }
    }
    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/android/awsomedemo/DemoTool->md5([B)Ljava/lang/String;":
                //return vm.resolveClass("com/android/awsomedemo/DemoTool").newObject(null);
                // return new StringObject(vm,"/sdcard/");
                int intArg = vaList.getIntArg(0);
                Object argobj = vm.getObject(intArg).getValue();
                String md5s = md5((byte[]) argobj);
                System.out.printf(">>>>>>>>>>>>>>>|%s|<<<<<<<<<<<<<<\n", md5s);
                StringObject ret = new StringObject(vm, md5s);
                vm.addLocalObject(ret);
                return ret;
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

     public static String md5(byte[] str) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(MessageDigestAlgorithms.MD5);
            messageDigest.update(str);
            byte[] digest = messageDigest.digest();
            StringBuffer stringBuffer = new StringBuffer("");
            for (int i = 0; i < digest.length; i++) {
                int i2 = digest[i];
                if (i2 < 0) {
                    i2 += 256;
                }
                if (i2 < 16) {
                    stringBuffer.append(CustomBooleanEditor.VALUE_0);
                }
                stringBuffer.append(Integer.toHexString(i2));
            }
            return stringBuffer.toString();
        } catch (Exception unused) {
            return UUID.randomUUID().toString();
        }
    }
    private static String w3(byte[] bArr) throws IOException {
        byte[] bArr2 = new byte[bArr.length + 1];
        System.arraycopy(bArr, 0, bArr2, 0, bArr.length);
        bArr2[bArr.length] = 0;
        InflaterInputStream inflaterInputStream = new InflaterInputStream(new ByteArrayInputStream(bArr));
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(512);
        while (true) {
            int read = inflaterInputStream.read();
            if (read == -1) {
                byteArrayOutputStream.close();
                return byteArrayOutputStream.toString();
            }
            byteArrayOutputStream.write(read);
        }
    }

    public JSONObject ttEncrypt(Map<String, String> headers, Map<String, String> params) throws JSONException, IOException {
        String token = params.get("X-TK");
        String x_no = params.get("X-NO");
        String x_ts = params.get("X-TS");
        String x_appid = params.get("X-APPID");
        String x_uid = params.get("X-UID");
        String x_ver = params.getOrDefault("X-VER", "2.128.0"); //2.128.0 固定，否则每次都要更新so
        String x_mk = params.get("X-MK");
        String x_dt = params.get("X-DT");
        String x_body = params.getOrDefault("X-BODY", "");
        // 执行Jni方法
        String equinn = TTEncryptUtils.callStaticJniMethodObject(emulator, "socialEQuinn()Ljava/lang/String;").toString().replace("\"", "");//9a7AzQUF9s5YQP6UGZKn8oRrkuZHJQ
        String[] strArr = new String[] {
            token, x_no, equinn, // "9a7AzQUF9s5YQP6UGZKn8oRrkuZHJQ",
            x_ts, x_appid, x_uid,
            x_ver, "2", x_mk
        };
       
        for (String str : strArr) {
            System.out.println(str);
        }
        // ArrayObject arrayObject = ArrayObject.newStringArray(vm, strArr);
        String key = TTEncryptUtils.callStaticJniMethodObject(emulator, "socialESona([Ljava/lang/String;)Ljava/lang/String;", 
            ArrayObject.newStringArray(vm, strArr)).toString().replace("\"", "");

        String urldec_xdt = URLDecoder.decode(x_dt, "UTF-8");
        String dec_xdt = TTEncryptUtils.callStaticJniMethodObject(emulator,
                "socialEJinx(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                key, urldec_xdt).toString();
        // 将获取的json数据封装一层，然后在给返回
        JSONObject ret = new JSONObject();
        ret.put("X-DT", dec_xdt);
        if (x_body.length() > 0) {
            String urldec_xbody = URLDecoder.decode(x_body, "UTF-8");
            String dec_xbody = TTEncryptUtils.callStaticJniMethodObject(emulator,
                    "socialEJinx(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                    key, urldec_xbody).toString();
            String unzip_xbody = w3(Base64.getDecoder().decode(dec_xbody.replace("\"", "")));
            ret.put("X-BODY", unzip_xbody);
        }
        return ret;

    }

}
