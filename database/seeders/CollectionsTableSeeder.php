<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class CollectionsTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $faker = \Faker\Factory::create();

        for ($i = 1; $i <= 5; $i++) {
            DB::table('collections')->insert([
                'code' => 'RLVCQOIA' . str_pad($i, 4, '0', STR_PAD_LEFT),  // RLVCQOIA0001, RLVCQOIA0002, etc.
                'name' => $faker->randomElement(['Skewer Shop', 'Noodle Shop', 'Coffee Shop', 'Tea House', 'Bakery']),
                'description' => $faker->sentence,
                'status' => $faker->randomElement(['active', 'inactive']),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }
    }
}
