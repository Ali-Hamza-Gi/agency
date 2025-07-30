<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();

            // Relationships
            $table->foreignId('agency_id')->nullable()->constrained('users')->nullOnDelete();

            // Basic Info
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->string('profile_image')->nullable();

            // Roles & Status
            $table->enum('role', ['super_admin', 'agency', 'admin', 'salesman', 'delivery_boy', 'accountant', 'retailer'])->default('retailer');
            $table->enum('status', ['active', 'inactive'])->default('active');

            // Verification
            $table->timestamp('email_verified_at')->nullable();

            // Login & Security
            $table->timestamp('last_login_at')->nullable();
            $table->string('last_login_ip')->nullable();
            $table->integer('failed_login_attempts')->default(0);
            $table->timestamp('locked_until')->nullable();
            $table->integer('token_version')->default(1);

            // Two-Factor Authentication
            $table->boolean('two_factor_enabled')->default(false);
            $table->boolean('is_two_factor_verified')->default(false);
            $table->string('two_factor_secret')->nullable();
            $table->string('two_factor_code')->nullable();
            $table->timestamp('two_factor_expires_at')->nullable();
            $table->json('two_factor_recovery_codes')->nullable();

            // Preferences
            $table->string('timezone')->default('Asia/Karachi');
            $table->string('language')->default('en');

            // Audit
            $table->foreignId('created_by')->nullable()->constrained('users')->nullOnDelete();
            $table->foreignId('updated_by')->nullable()->constrained('users')->nullOnDelete();
            $table->foreignId('deleted_by')->nullable()->constrained('users')->nullOnDelete();

            // Laravel defaults
            $table->rememberToken();
            $table->softDeletes();
            $table->timestamps();
        });


        Schema::create('password_reset_tokens', function (Blueprint $table) {
            $table->string('email')->primary();
            $table->string('token');
            $table->timestamp('created_at')->nullable();
        });

        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
        Schema::dropIfExists('password_reset_tokens');
        Schema::dropIfExists('sessions');
    }
};
