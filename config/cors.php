<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Cross-Origin Resource Sharing (CORS) Configuration
    |--------------------------------------------------------------------------
    |
    | Controls how your API responds to cross-origin requests. You may adjust
    | the settings below as needed for your frontend apps and environments.
    |
    */

    'paths' => ['api/*', 'v1/web/*', 'login', 'logout', 'refresh', 'sanctum/csrf-cookie'],
    'allowed_methods' => ['*'],
    'allowed_origins' => [
        'http://localhost:5173',
        'http://192.168.18.27:8000',
    ], // Add your production domain
    'allowed_origins_patterns' => [],
    'allowed_headers' => ['*'],
    'exposed_headers' => [],
    'max_age' => 0,
    'supports_credentials' => true,

];
