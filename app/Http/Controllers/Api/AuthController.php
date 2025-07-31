<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use App\Helpers\ApiResponse;
use Illuminate\Http\Request;
use App\Events\UserRegistered;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6'
        ]);

        if ($validator->fails()) {
            return ApiResponse::validationError($validator->errors());
        }

        $credentials = $request->only('email', 'password');

        if (!$token = JWTAuth::attempt($credentials)) {
            return ApiResponse::error('Invalid credentials', 401);
        }

        $user = Auth::user();
        $user->update([
            'last_login_at' => now(),
            'last_login_ip' => $request->ip(),
            'is_two_factor_verified' => false,
        ]);

        if ($user->two_factor_enabled) {
            $user->generateTwoFactorCode();
            $tempToken = JWTAuth::claims([
                'two_factor_pending' => true,
                'exp' => now()->addMinutes(10)->timestamp
            ])->fromUser($user);

            return ApiResponse::success([
                'two_factor_required' => true,
                'temp_token' => $tempToken,
            ], '2FA verification required');
        }

        $refreshToken = JWTAuth::claims(['type' => 'refresh'])->fromUser($user);

        return $this->respondWithTokens($token, $refreshToken, $user);
    }

public function respondWithTokens($token, $refreshToken, $user)
{
    return response()
        ->json([
            'success' => true,
            'user' => $user->only(['id', 'name', 'email'])
        ])
        ->withCookie(
            cookie(
                config('jwt.cookie', 'token'),
                $token,
                config('jwt.access_ttl', 1440),
                '/',
                config('jwt.cookie_domain'),
                config('jwt.cookie_secure'),
                true,
                false,
                config('jwt.cookie_samesite', 'lax')
            )
        )
        ->withCookie(
            cookie(
                'refresh_token',
                $refreshToken,
                config('jwt.refresh_ttl', 10080),
                '/',
                config('jwt.cookie_domain'),
                config('jwt.cookie_secure'),
                true,
                false,
                config('jwt.cookie_samesite', 'lax')
            )
        );
}

    public function refresh(Request $request)
    {
        try {
            $refreshToken = $request->cookie('refresh_token');

            if (!$refreshToken) {
                return ApiResponse::error('Refresh token missing', 401);
            }

            $user = JWTAuth::setToken($refreshToken)->authenticate();
            $newToken = JWTAuth::fromUser($user);

            return ApiResponse::success()->withCookie(
                cookie(
                    config('jwt.cookie', 'token'),
                    $newToken,
                    config('jwt.access_ttl', 1440),
                    '/',
                    config('jwt.cookie_domain'),
                    config('jwt.cookie_secure'),
                    true,
                    false,
                    config('jwt.cookie_samesite', 'lax')
                )
            );
        } catch (\Exception $e) {
            return ApiResponse::error('Token refresh failed', 401);
        }
    }

    public function logout()
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
        } catch (\Exception $e) {
            // Continue even if token invalidation fails
        }

        return ApiResponse::success([], 'Logged out')->withCookies([
            cookie()->forget(config('jwt.cookie', 'token')),
            cookie()->forget('refresh_token')
        ]);
    }

    public function me()
    {
        return ApiResponse::success(auth()->user());
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return ApiResponse::validationError($validator->errors());
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // event(new UserRegistered($user));

        return ApiResponse::success([
            'user' => $user->only(['id', 'name', 'email']),
        ], 'Registration successful', 200);
    }
}
