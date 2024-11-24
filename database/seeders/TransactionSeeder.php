<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Transaction;
use Faker\Factory as Faker;

class TransactionSeeder extends Seeder
{
    public function run()
    {
        $faker = Faker::create();

        // Create 20 'paid' transactions
        for ($i = 0; $i < 20; $i++) {
            Transaction::create([
                'code' => $faker->regexify('[A-Z0-9]{16}'),
                'status' => 'paid',
                'amount' => $faker->randomFloat(2, 5, 500),
                'payment_description' => $faker->sentence(3),
                'payment_description2' => $faker->sentence(3), // Generate data for new column
                'due_date' => $faker->dateTimeBetween('-1 month', '+1 month'),
                'payer_name' => $faker->name,
                'payer_email' => $faker->unique()->safeEmail,
                'payer_phone' => $faker->numerify('60##########'),
            ]);
        }

        // Create 10 'unpaid' transactions
        for ($i = 0; $i < 10; $i++) {
            Transaction::create([
                'code' => $faker->regexify('[A-Z0-9]{16}'),
                'status' => 'unpaid',
                'amount' => $faker->randomFloat(2, 5, 500),
                'payment_description' => $faker->sentence(3),
                'payment_description2' => $faker->sentence(3), // Generate data for new column
                'due_date' => $faker->dateTimeBetween('-1 month', '+1 month'),
                'payer_name' => $faker->name,
                'payer_email' => $faker->unique()->safeEmail,
                'payer_phone' => $faker->numerify('60##########'),
            ]);
        }

        // Create 5 'expired' transactions
        for ($i = 0; $i < 5; $i++) {
            Transaction::create([
                'code' => $faker->regexify('[A-Z0-9]{16}'),
                'status' => 'expired',
                'amount' => $faker->randomFloat(2, 5, 500),
                'payment_description' => $faker->sentence(3),
                'payment_description2' => $faker->sentence(3), // Generate data for new column
                'due_date' => $faker->dateTimeBetween('-1 month', '+1 month'),
                'payer_name' => $faker->name,
                'payer_email' => $faker->unique()->safeEmail,
                'payer_phone' => $faker->numerify('60##########'),
            ]);
        }
    }
}
