<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Helpers\ApiResponse;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return ApiResponse::error('Invalid credentials', [], 401);
            }
        } catch (JWTException $e) {
            return ApiResponse::error('Could not create token', ['exception' => $e->getMessage()], 500);
        }

        // Cookie configuration
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

        return ApiResponse::success(null, 'Login successful')->withCookie($cookie);
    }

    public function logout()
    {
        $forgetCookie = cookie()->forget(config('jwt.cookie', 'token'));

        return ApiResponse::success(null, 'Logout successful')->withCookie($forgetCookie);
    }

    public function me()
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            return ApiResponse::success($user, 'User fetched');
        } catch (\Exception $e) {
            return ApiResponse::error('Unauthorized', [], 401);
        }
    }
}
