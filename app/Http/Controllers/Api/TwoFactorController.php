<?php

namespace App\Http\Controllers\Api;

use App\Helpers\ApiResponse;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;

class TwoFactorController extends Controller
{
    public function verify(Request $request)
    {
        $request->validate(['code' => 'required|string']);

        $user = Auth::user();

        if (!$user->two_factor_enabled) {
            return ApiResponse::error('2FA not enabled', 400);
        }

        if ($user->two_factor_code &&
            $user->two_factor_expires_at &&
            now()->lessThan($user->two_factor_expires_at) &&
            $request->code === $user->two_factor_code) {

            $user->resetTwoFactorCode();

            // Generate new tokens since 2FA is now verified
            $token = JWTAuth::fromUser($user);
            $refreshToken = JWTAuth::claims(['type' => 'refresh'])->fromUser($user);

            return $this->respondWithTokens($token, $refreshToken, $user);
        }

        return ApiResponse::error('Invalid 2FA code', 401);
    }

    public function enable(Request $request)
    {
        $user = Auth::user();

        if ($user->two_factor_enabled) {
            return ApiResponse::error('2FA already enabled', 400);
        }

        $user->two_factor_enabled = true;
        $user->save();

        return ApiResponse::success([], '2FA enabled successfully');
    }

    public function disable(Request $request)
    {
        $user = Auth::user();

        if (!$user->two_factor_enabled) {
            return ApiResponse::error('2FA not enabled', 400);
        }

        $user->two_factor_enabled = false;
        $user->two_factor_code = null;
        $user->two_factor_expires_at = null;
        $user->is_two_factor_verified = false;
        $user->save();

        return ApiResponse::success([], '2FA disabled successfully');
    }

    protected function respondWithTokens($token, $refreshToken, $user)
    {
        return ApiResponse::success([
            'user' => $user->only(['id', 'name', 'email']),
        ])->withCookies([
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
            ),
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
        ]);
    }
}
