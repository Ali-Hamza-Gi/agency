<?php

namespace App\Http\Controllers\Api;

use App\Helpers\ApiResponse;
use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;

class TwoFactorController extends Controller
{
    /**
     * Verify a 2FA code (or recovery code) after login
     */
    public function verify(Request $request)
    {
        $request->validate([
            'code' => 'required|string'
        ]);

        $user = JWTAuth::parseToken()->authenticate();
        if (!$user) return ApiResponse::error('Unauthorized', 401);

        // Check if code matches and is valid
        if ($user->verifyTwoFactorCode($request->code)) {
            $user->resetTwoFactorCode();
            return ApiResponse::success(['message' => '2FA verification successful']);
        }

        // Check recovery codes
        if ($user->verifyRecoveryCode($request->code)) {
            $user->resetTwoFactorCode();
            return ApiResponse::success(['message' => '2FA verified using recovery code']);
        }

        return ApiResponse::error('Invalid or expired 2FA code', 422);
    }

    /**
     * Enable 2FA (generate recovery codes)
     */
    public function enable(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();
        if (!$user) return ApiResponse::error('Unauthorized', 401);

        if ($user->two_factor_enabled) {
            return ApiResponse::error('Two-factor authentication is already enabled');
        }

        // Generate recovery codes (plain + hashed)
        $codes = User::generateRecoveryCodes();

        $user->update([
            'two_factor_enabled' => true,
            'two_factor_recovery_codes' => json_encode(
                collect($codes)->map(fn($c) => ['hashed' => $c['hashed']])->toArray()
            )
        ]);

        return ApiResponse::success([
            'message' => 'Two-factor authentication enabled',
            'recovery_codes' => collect($codes)->pluck('plain') // Show only once
        ]);
    }

    /**
     * Disable 2FA
     */
    public function disable(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();
        if (!$user) return ApiResponse::error('Unauthorized', 401);

        $user->update([
            'two_factor_enabled' => false,
            'two_factor_code' => null,
            'two_factor_expires_at' => null,
            'is_two_factor_verified' => false,
            'two_factor_recovery_codes' => null
        ]);

        return ApiResponse::success(['message' => 'Two-factor authentication disabled']);
    }

    /**
     * Regenerate recovery codes
     */
    public function regenerateCodes(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();
        if (!$user) return ApiResponse::error('Unauthorized', 401);

        $codes = User::generateRecoveryCodes();

        $user->update([
            'two_factor_recovery_codes' => json_encode(
                collect($codes)->map(fn($c) => ['hashed' => $c['hashed']])->toArray()
            )
        ]);

        return ApiResponse::success([
            'message' => 'Recovery codes regenerated',
            'recovery_codes' => collect($codes)->pluck('plain') // Only show once
        ]);
    }
}
