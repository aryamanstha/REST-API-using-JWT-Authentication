<?php

namespace App\Http\Controllers;


use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;



class AuthController extends Controller
{
    //Contructor class to define the 'auth' middleware and 'api' guard for the requests
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    //User Registration Function
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|email',
            'password' => 'required|confirmed'
        ]);
        if ($validator->fails()) {
            return response()->json([
                $validator->errors()->toJson()
            ], 422);
        }
        $user = User::create(array_merge($validator->validated()), [
            'password' => bcrypt($request->password)
        ]);

        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], 201);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string'
        ]);
        if ($validator->fails()) {
            return response()->json([
                $validator->errors()->toJson()
            ], 422);
        }
        $token = auth()->attempt($validator->validated());
        if (!$token) {
            return response()->json([
                'message' => 'Invalid email or password',
            ], 401);
        }
        return $this->createNewToken($token);
    }

    //Creating New Token

    public function createNewToken($token)
    {
        return response()->json([
            'token' => $token,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL() * 60,
            'user' => auth()->user(),
        ]);
    }

    //Logout
    public function logout()
    {
        Auth::logout();
        return response()->json([
            'message' => 'User Logged Out Successfully'
        ], 200);
    }

    //Refresh the token
    public function refresh()
    {
    return $this->createNewToken(Auth::refresh());
    }

    //Show User Profile
    public function user_profile()
    {
        $user=auth()->user();
        return response()->json([
            'message'=>'User Data',
            'User'=>$user
        ],200);
    }
}
