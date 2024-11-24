<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
{
    Schema::create('transactions', function (Blueprint $table) {
        $table->id();
        $table->string('code');
        $table->enum('status', ['paid', 'unpaid', 'expired']);
        $table->decimal('amount', 8, 2);
        $table->string('payment_description');
        $table->string('payment_description2')->nullable();
        $table->timestamp('due_date');
        $table->string('payer_name');
        $table->string('payer_email');
        $table->string('payer_phone');
        $table->timestamps();
    });
}

public function down()
{
    Schema::dropIfExists('transactions');
}

};
