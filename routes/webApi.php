<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\TwoFactorController;

Route::prefix('v1/web')->group(function () {
    // Public routes
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/refresh', [AuthController::class, 'refresh']);

    // Authenticated routes (JWT verified)
    Route::middleware('jwt.cookie')->group(function () {
        // Two-factor routes
        Route::prefix('2fa')->group(function () {
            Route::post('/verify', [TwoFactorController::class, 'verify']);
            Route::post('/enable', [TwoFactorController::class, 'enable']);
            Route::post('/disable', [TwoFactorController::class, 'disable']);
            Route::post('/regenerate-codes', [TwoFactorController::class, 'regenerateCodes']);
        });

        Route::post('/logout', [AuthController::class, 'logout']);

        // 2FA verified routes
        Route::middleware('2fa.verified')->group(function () {
            Route::get('/me', [AuthController::class, 'me']);
            // Add other protected routes here
        });
    });
});
