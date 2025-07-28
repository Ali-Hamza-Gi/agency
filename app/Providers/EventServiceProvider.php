<?php

namespace App\Providers;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use App\Events\UserRegistered;
use App\Listeners\GenerateRecoveryCodes;

class EventServiceProvider extends ServiceProvider
{
    public function register(): void {}

    public function boot(): void
    {
        Event::listen(
            UserRegistered::class,
            GenerateRecoveryCodes::class,
        );
    }
}
