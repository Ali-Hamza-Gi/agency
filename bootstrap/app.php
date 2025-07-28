<?php

use App\Helpers\ApiResponse;
use Illuminate\Http\Request;
use Illuminate\Foundation\Application;
use App\Http\Middleware\JwtCookieMiddleware;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__ . '/../routes/web.php',
        api: __DIR__ . '/../routes/api.php',
        commands: __DIR__ . '/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // Global middleware (runs on every request)
        // $middleware->append(JwtCookieMiddleware::class); // Uncomment only if needed globally

        // Register as route middleware
        $middleware->alias([
            'jwt.cookie' => JwtCookieMiddleware::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {

        $exceptions->render(function (AuthenticationException $e, Request $request) {
            if ($request->is('api/*')) {
                $message = app()->environment('local')
                    ? $e->getMessage()
                    : 'Authentication required. Please log in.';
                return ApiResponse::error($message, 401);
            }
        });

        $exceptions->render(function (ValidationException $e, Request $request) {
            if ($request->is('api/*')) {
                return ApiResponse::validationError($e->errors(), 'Validation failed');
            }
        });

        $exceptions->render(function (NotFoundHttpException $e, Request $request) {
            if ($request->is('api/*')) {
                $message = app()->environment('local') ? $e->getMessage() : 'Resource not found.';
                return ApiResponse::error($message, 404);
            }
        });

        $exceptions->render(function (\Exception $e, Request $request) {
            if ($request->is('api/*')) {
                $message = app()->environment('local') ? $e->getMessage() : 'An unexpected error occurred. Please try again later.';
                return ApiResponse::error($message, 500);
            }
        });
    })->create();
