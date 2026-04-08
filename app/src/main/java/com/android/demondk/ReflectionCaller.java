package com.android.demondk;

import android.util.Log;
import java.lang.reflect.Method;

public class ReflectionCaller {

    public static void callAddMethod() {
        try {
            // 1. 获取目标类的 Class 对象
            // 方式 A: 如果编译时知道类名
            Class<?> clazz = Class.forName("com.android.demondk.PrintTest");

            // 方式 B: 如果已经有实例对象 (这里是静态方法，用不到，但列出来供参考)
            // PrintTest instance = new PrintTest();
            // Class<?> clazz = instance.getClass();

            Log.i("Reflection", "Class found: " + clazz.getName());

            // 2. 获取目标方法的 Method 对象
            // 参数：方法名, 参数类型的 Class 数组
            // 因为 add(int a, int b) 接收两个 int，所以要传入 int.class
            Method addMethod = clazz.getMethod("add", int.class, int.class);

            // 如果方法是 private 的，需要用 getDeclaredMethod() 并设置 setAccessible(true)
            // Method addMethod = clazz.getDeclaredMethod("add", int.class, int.class);
            // addMethod.setAccessible(true); // 暴力反射，绕过访问权限检查

            Log.i("Reflection", "Method found: " + addMethod.getName());

            // 3. 调用方法 (invoke)
            // 参数：调用该方法的对象实例, 方法的参数列表
            // 因为 add 是 static 方法，所以第一个参数传 null
            // 如果是实例方法，这里需要传具体的对象实例，比如 instance.add(...)
            Object[] args = {100, 200};
            Object result = addMethod.invoke(null, args); // 静态方法，实例为 null

            // 4. 处理返回值
            // 返回值是 Object 类型，需要强制转换为具体的类型 (这里是 Integer)
            int sum = (Integer) result;

            Log.i("Reflection", "Method invoked successfully! Result: " + sum);
            // 预期 Logcat 输出: Method invoked successfully! Result: 300

        } catch (ClassNotFoundException e) {
            Log.e("Reflection", "Class not found", e);
        } catch (NoSuchMethodException e) {
            Log.e("Reflection", "Method not found", e);
        } catch (Exception e) {
            // 捕获 InvocationTargetException (方法内部抛出的异常) 或 IllegalAccessException
            Log.e("Reflection", "Error invoking method", e);
        }
    }
}
