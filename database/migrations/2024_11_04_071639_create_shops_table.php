<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('shops', function (Blueprint $table) {
            $table->id(); // Shop ID
            $table->string('name'); // Shop Name
            $table->text('description')->nullable(); // Shop Description
            $table->date('date_created'); // Date Created
            $table->enum('status', ['active', 'inactive'])->default('inactive'); // Status
            $table->json('payment_used')->nullable(); // Payment Used (OBW/QR/MPGS)
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::dropIfExists('shops');
    }
};
