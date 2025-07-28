<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use App\Helpers\ApiResponse;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use App\Events\UserRegistered;

class AuthController extends Controller
{
    /**
     * Login user and set access & refresh tokens in cookies
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

        $user = Auth::user();

        // Track login info
        $user->update([
            'last_login_at' => now(),
            'last_login_ip' => $request->ip(),
            'failed_login_attempts' => 0,
            'is_two_factor_verified' => false, // reset 2FA verification
        ]);

        // If 2FA is enabled → require verification before issuing tokens
        if ($user->two_factor_enabled) {
            $user->generateTwoFactorCode();
            return ApiResponse::success([
                'two_factor_required' => true,
                'message' => '2FA verification code sent to your email.'
            ], 'Two-factor verification required');
        }

        // Create refresh token
        $refreshToken = JWTAuth::claims(['type' => 'refresh'])->fromUser($user);

        // Set cookies
        $accessCookie = cookie(
            config('jwt.cookie', 'token'),
            $token,
            env('JWT_COOKIE_DURATION', 1440), // 24h
            '/',
            env('JWT_COOKIE_DOMAIN', null),
            filter_var(env('JWT_COOKIE_SECURE', false), FILTER_VALIDATE_BOOLEAN),
            true,
            false,
            env('JWT_COOKIE_SAMESITE', 'Lax')
        );

        $refreshCookie = cookie(
            'refresh_token',
            $refreshToken,
            10080, // 7 days
            '/',
            env('JWT_COOKIE_DOMAIN', null),
            filter_var(env('JWT_COOKIE_SECURE', false), FILTER_VALIDATE_BOOLEAN),
            true,
            false,
            env('JWT_COOKIE_SAMESITE', 'Lax')
        );

        return ApiResponse::success([
            'token' => $token,
            'refresh_token' => $refreshToken,
            'user' => $user
        ], 'Login successful')->withCookie($accessCookie)->withCookie($refreshCookie);
    }

    /**
     * Refresh access token using refresh token
     */
    public function refresh(Request $request)
    {
        try {
            $refreshToken = $request->cookie('refresh_token');
            if (!$refreshToken) {
                return ApiResponse::error('Refresh token missing', 401);
            }

            $user = JWTAuth::setToken($refreshToken)->authenticate();
            if (!$user) {
                return ApiResponse::error('Invalid refresh token', 401);
            }

            $newToken = JWTAuth::fromUser($user);

            $accessCookie = cookie(
                config('jwt.cookie', 'token'),
                $newToken,
                env('JWT_COOKIE_DURATION', 1440),
                '/',
                env('JWT_COOKIE_DOMAIN', null),
                filter_var(env('JWT_COOKIE_SECURE', false), FILTER_VALIDATE_BOOLEAN),
                true,
                false,
                env('JWT_COOKIE_SAMESITE', 'Lax')
            );

            return ApiResponse::success(['token' => $newToken], 'Token refreshed')->withCookie($accessCookie);
        } catch (\Exception $e) {
            return ApiResponse::error('Token refresh failed', 401, ['exception' => $e->getMessage()]);
        }
    }

    /**
     * Logout user - invalidate tokens & clear cookies
     */
    public function logout()
    {
        try {
            $token = JWTAuth::getToken();
            if ($token) {
                JWTAuth::invalidate($token);
            }
        } catch (\Exception $e) {
            // Ignore invalid tokens
        }

        $forgetAccess = cookie()->forget(config('jwt.cookie', 'token'));
        $forgetRefresh = cookie()->forget('refresh_token');

        return ApiResponse::success([], 'Logout successful')->withCookie($forgetAccess)->withCookie($forgetRefresh);
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
     * Register a new user & generate recovery codes
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'     => 'required|string|max:255',
            'email'    => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return ApiResponse::validationError($validator->errors());
        }

        try {
            $user = User::create([
                'name'     => $request->name,
                'email'    => $request->email,
                'password' => Hash::make($request->password),
            ]);

            // Generate recovery codes
            $codes = User::generateRecoveryCodes();
            event(new UserRegistered($user, collect($codes)->pluck('plain')));

            $userData = $user->only(['id', 'name', 'email', 'created_at']);

            return ApiResponse::success([
                'user' => $userData,
                'recovery_codes' => collect($codes)->pluck('plain') // show only once
            ], 'Registration successful', 201);
        } catch (\Exception $e) {
            return ApiResponse::error('Registration failed', 500, ['exception' => $e->getMessage()]);
        }
    }
}
