<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateBillingsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('billings', function (Blueprint $table) {
            $table->id();
            $table->string('code', 18)->unique();
            $table->string('belong_to_collection');  // Foreign key (code from collections table)
            $table->enum('status', ['paid', 'unpaid', 'expired']);
            $table->decimal('amount', 10, 2);        // Decimal value for amount
            $table->string('payment_description')->nullable();
            $table->string('payment_description2')->nullable();
            $table->timestamp('due_date');
            $table->string('payer_name');
            $table->string('payer_email');
            $table->string('payer_phone');
            $table->enum('payment_method', ['OBW', 'MPGS', 'QR Pay'])->default('QR Pay');
            $table->timestamps();

            // Foreign key constraint to ensure collection code exists
            $table->foreign('belong_to_collection')->references('code')->on('collections')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('billings');
    }
}

