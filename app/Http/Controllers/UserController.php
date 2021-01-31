<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use JWTAuth;
use Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Response;

class UserController extends Controller
{
    public $token = true;
  
    public function register(Request $request)
    {
 
        $validator = Validator::make($request->all(), 
		  [ 
		  'name' => 'required',
		  'email' => 'required|email',
		  'password' => 'required',  
		  'c_password' => 'required|same:password', 
		]);  
 
        if ($validator->fails()) {  
            return response()->json(['error'=>$validator->errors()], 401); 
        }   
 
 
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();
  
        if ($this->token) {
            return $this->login($request);
        }
  
        return response()->json([
            'success' => true,
            'data' => $user
        ], Response::HTTP_OK);
    }
  
    public function login(Request $request)
    {
		$validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);
		
		if ($validator->fails()) {  
		   return response()->json(['error'=>$validator->errors()], 401); 
		}   
		
        //$input = $request->only('email', 'password');
        $jwt_token = null;
  
        if (!$jwt_token = JWTAuth::attempt($validator->validated())) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid Email or Password',
            ], Response::HTTP_UNAUTHORIZED);
        }
  
        return response()->json([
            'success' => true,
            'token' => $jwt_token,
        ]);
    }
  
    public function logout(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);
  
        try {
            JWTAuth::invalidate($request->token);
  
            return response()->json([
                'success' => true,
                'message' => 'User logged out successfully'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Sorry, the user cannot be logged out'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
  
    public function getUser(Request $request)
    { 
        $auth_check = JWTAuth::parseToken()->authenticate();
        if($auth_check){
			$user = JWTAuth::authenticate($request->token);
			return response()->json(['user' => $user]);
		}else{
            return response()->json([
                'success' => false,
                'message' => 'Sorry, token is an invalid'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        } 
    }
}
