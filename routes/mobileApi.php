<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

Route::prefix('v1/app')->group(function () {

    // Public routes
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/logout', [AuthController::class, 'logout']);

    // Protected routes
    Route::middleware('jwt.cookie')->group(function () {
        Route::get('/me', [AuthController::class, 'me']);
    });
});
