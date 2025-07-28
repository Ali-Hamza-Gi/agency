<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

Route::prefix('v1/web')->group(function () {

    // Public routes
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/register', [AuthController::class, 'register']);

    // Protected routes
    Route::middleware('jwt.cookie')->group(function () {
        Route::get('/me', [AuthController::class, 'me']);
    });
});
