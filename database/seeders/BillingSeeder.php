<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Billing;
use Faker\Factory as Faker;

class BillingSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $faker = Faker::create();

        for ($i = 1; $i <= 20; $i++) {
            Billing::create([
                'code' => 'RLV' . str_pad($i, 15, '20', STR_PAD_LEFT),
                'belong_to_collection' => 'RLVCQOIA000' . rand(1, 5),  // Assuming there are 5 collections
                'status' => $faker->randomElement(['paid', 'unpaid']),
                'amount' => $faker->randomFloat(2, 10, 1000),
                'payment_description' => $faker->sentence,
                'payment_description2' => $faker->sentence,
                'due_date' => $faker->dateTimeBetween('2024-10-02', '2024-10-08'),
                'payer_name' => $faker->name,
                'payer_email' => $faker->email,
                'payer_phone' => $faker->phoneNumber,
                'payment_method' => $faker->randomElement(['QR Pay', 'OBW', 'MPGS']),
            ]);
        }
    }
}
