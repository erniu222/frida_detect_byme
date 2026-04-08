package com.android.demondk;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.android.demondk.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'demondk' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(stringFromJNI());
        ReflectionCaller.callAddMethod();
//        PrintTest.add(1, 2);// 这个是纯纯的走解释执行那个模式，最后是Execute方法，但是如果是jit或者oat，可能也就不走这个这个流程了
    }


    public void print(){
        Log.e("erniu", "this is a test");
    }
    /**
     * A native method that is implemented by the 'demondk' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}