<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;

class ForgotPasswordController extends Controller
{
    public function forgot(Request $request) {
        $this->validate($request,[
            'email' => 'required|email'
        ]);

        $email = $request->email;

        if (User::where('email', $email)->doesntExist()) {
            return response()->json(['message' => 'Email Does not exists.'], 200);
        }

        $token = Str::random(10);

        DB::table('password_resets')->insert([
            'email' => $email,
            'token' => $token,
            'created_at' => now()->addHours(6)
        ]);

        Mail::send('mail.password_reset_mail', ['token' => $token], function ($message) use($email) {
            $message->to($email);
            $message->subject('Reset Yout Password');
        });

        return response()->json(['message' => 'Check your email.'], 200);
    }

    public function reset(Request $request) {
        $this->validate($request, [
            'token' => 'required|string',
            'password' => 'required|string|confirmed'
        ]);

        $token = $request->token;
        $passwordRest = DB::table('password_resets')->where('token', $token)->first();

        if (!$passwordRest) {
            return response()->json(['message' => 'Token Not Found.'], 200);
        }

        if (!$passwordRest->created_at >= now()) {
            return response()->json(['message' => 'Token has expired.'], 200);
        }

        $user = User::where('email', $passwordRest->email)->first();

        if (!$user) {
            return response()->json(['message' => 'User does not exists'], 200);
        }

        $user->password = Hash::make($request->password);
        $user->save();

        DB::table('password_resets')->where('token', $token)->delete();

        return response()->json(['message' => 'Password Successfully Update'], 200);
    }
}
