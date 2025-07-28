<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\TwoFactorController;

Route::prefix('v1/web')->group(function () {

    // Public routes
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/refresh', [AuthController::class, 'refresh']);

    // Authenticated but not necessarily 2FA-verified
    Route::middleware('jwt.cookie')->group(function () {

        // Two-factor management
        Route::prefix('2fa')->group(function () {
            Route::post('/verify', [TwoFactorController::class, 'verify']);       // Enter 2FA code
            Route::post('/enable', [TwoFactorController::class, 'enable']);       // Enable 2FA
            Route::post('/disable', [TwoFactorController::class, 'disable']);     // Disable 2FA
            Route::post('/regenerate-codes', [TwoFactorController::class, 'regenerateCodes']); // Regenerate codes
        });

        Route::post('/logout', [AuthController::class, 'logout']);

        // Fully 2FA-verified routes
        Route::middleware('2fa.verified')->group(function () {
            Route::get('/me', [AuthController::class, 'me']); // Example: account details
            // Add more protected routes here (profile update, payments, orders, etc.)
        });
    });
});
