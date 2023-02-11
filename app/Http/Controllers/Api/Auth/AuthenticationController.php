<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthenticationController extends Controller
{
    public function login(Request $request) {
        $this->validate($request,[
            'email' => 'required|max:255',
            'password' => 'required'
        ]);

        $login = $request->only('email', 'password');

        if (!Auth::attempt($login)) {
            return response()->json(['message' => 'Invalid login credential!'], 401);
        }

        $user = Auth::user();
        $token = $user->createToken($user->name);

        return response()->json([
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'created_at' => $user->created_at,
            'updated_at' => $user->updated_at,
            'token' => $token->accessToken,
            'token_expires_at' => $token->token->expires_at,
        ],200);
    }

    public function logout(Request $request) {
        $this->validate($request,[
            'allDevice' => 'required'
        ]);

        $user = Auth::user();

        if ($request->allDevice) {
            $user->token->each(function($token){
                $token->delete();
            });
            return response()->json(['message' => 'Logged out from all device!!!'], 200);
        }
        $userToken = $user->token();
        $userToken->delete();
        return response()->json(['message' => 'Logged successfull!!!'], 200);
    }
}
