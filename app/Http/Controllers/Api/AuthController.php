<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Helpers\ApiResponse;
use App\Models\User;

class AuthController extends Controller
{
    /**
     * Login user and set JWT token in cookie
     */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return ApiResponse::error('Invalid credentials', 401);
            }
        } catch (JWTException $e) {
            return ApiResponse::error('Could not create token', 500, ['exception' => $e->getMessage()]);
        }

        // Cookie configuration for JWT
        $cookie = cookie(
            config('jwt.cookie', 'token'),
            $token,
            env('JWT_COOKIE_DURATION', 1440),
            '/',
            env('JWT_COOKIE_DOMAIN', null),
            filter_var(env('JWT_COOKIE_SECURE', false), FILTER_VALIDATE_BOOLEAN),
            true, // HttpOnly
            false, // raw
            env('JWT_COOKIE_SAMESITE', 'Lax')
        );
        $user = JWTAuth::parseToken()->authenticate();
        $data = [
            'token' => $token,
            'user' => $user
        ];
        return ApiResponse::success($data, 'Login successful')->withCookie($cookie);
    }

    /**
     * Logout user and clear JWT cookie
     */
    public function logout()
    {
        $forgetCookie = cookie()->forget(config('jwt.cookie', 'token'));
        return ApiResponse::success([], 'Logout successful')->withCookie($forgetCookie);
    }

    /**
     * Get the authenticated user
     */
    public function me()
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            return ApiResponse::success($user, 'User fetched');
        } catch (\Exception $e) {
            return ApiResponse::error('Unauthorized', 401);
        }
    }

    /**
     * Register a new user (No token or cookie)
     */
    public function register(Request $request)
    {
        // Validate user input
        $validator = Validator::make($request->all(), [
            'name'     => 'required|string|max:255',
            'email'    => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return ApiResponse::validationError($validator->errors());
        }

        try {
            // Create new user
            $user = User::create([
                'name'     => $request->name,
                'email'    => $request->email,
                'password' => Hash::make($request->password),
            ]);

            // Hide sensitive fields before returning
            $userData = $user->only(['id', 'name', 'email', 'created_at']);

            return ApiResponse::success($userData, 'Registration successful', 201);
        } catch (\Exception $e) {
            return ApiResponse::error('Registration failed', 500, ['exception' => $e->getMessage()]);
        }
    }
}
