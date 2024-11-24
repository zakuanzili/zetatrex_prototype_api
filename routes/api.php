<?php

use App\Http\Controllers\Api\V1\AuthController;
use App\Http\Controllers\Api\V1\BillingController;
use App\Http\Controllers\Api\V1\CollectionController;
use App\Http\Controllers\Api\V1\CustomerController;
use App\Http\Controllers\Api\V1\InvoiceController;
use App\Http\Controllers\Api\V1\ShopController;
use App\Http\Controllers\Api\V1\TransactionController;
use App\Http\Controllers\Api\V1\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Models\User;

// Web login route using Sanctum
Route::post('v1/login', [AuthController::class, 'webLogin']);

// Mobile login route using Firebase
Route::post('v1/mobile-login', [AuthController::class, 'mobileLogin']);

// Authenticated user information
Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

// API routes with Sanctum authentication
Route::group(['prefix' => 'v1', 'namespace' => 'App\Http\Controllers\Api\V1', 'middleware' => 'auth:sanctum'], function () {
    
    // Customer routes
    Route::apiResource('customers', CustomerController::class);

    // Invoice routes
    Route::apiResource('invoices', InvoiceController::class);
    Route::post('invoices/bulk', [InvoiceController::class, 'bulkStore']);

    // Transaction routes
    Route::apiResource('transactions', TransactionController::class);
    Route::post('/transactions', [TransactionController::class, 'store']);

    // Shop routes (added for shop access based on user token)
    Route::get('/shops', [ShopController::class, 'index'])->name('shops.index');   // GET list of accessible shops
    Route::get('/shops/{id}', [ShopController::class, 'show'])->name('shops.show'); // GET specific shop by ID if authorized

    // List only collections
    Route::get('/collections', [CollectionController::class, 'listCollections']);

    // List collections based on shop code
    Route::get('/shops/{shopCode}/collections', [CollectionController::class, 'getCollectionsByShopCode']);

    // List collections based on shop code with billings
    Route::get('/shops/{shopCode}/collections/billings', [CollectionController::class, 'getCollectionsByShopCodeWithBillings']);

    // List collections with billings   
    Route::get('/collections-with-billings', [CollectionController::class, 'listCollectionsWithBillings']);

    // List billings by collection code
    Route::get('/collections/{collectionCode}/billings', [CollectionController::class, 'listBillingsByCollectionCode']);
    
    // Collection routes (with updated GET routes for viewing collections)
    Route::get('collections/{id}', [CollectionController::class, 'show']);     // GET specific collection by ID
    Route::post('collections', [CollectionController::class, 'store']);        // POST create a new collection
    Route::put('collections/{id}', [CollectionController::class, 'update']);   // PUT update a collection
    Route::delete('collections/{id}', [CollectionController::class, 'destroy']); // DELETE a collection

    // Billing routes
    Route::get('billings', [BillingController::class, 'index']);              // GET all billings
    Route::get('billings/{code}', [BillingController::class, 'show']);        // GET specific billing by code
    Route::post('billings', [BillingController::class, 'store']);             // POST create a new billing
    Route::post('/collections/{collectionCode}/billings', [BillingController::class, 'createBillingForCollection']);     // POST create a new billing based on a collection
    Route::put('billings/{code}', [BillingController::class, 'update']);      // PUT update an existing billing
    Route::delete('billings/{code}', [BillingController::class, 'destroy']);  // DELETE a billing

    // Save FCM Token (New Route)
    Route::post('/save-fcm-token', [UserController::class, 'saveFCMToken'])->name('user.saveFCMToken');

});

// Token generation route
// Route::post('generate-tokens', function () {
//     $user = User::find(1); // Or dynamically find the logged-in user
    
//     // Token for all five collections
//     $token = $user->createToken('Collection Access Token', [
//         'view-RLVCQOIA0001',
//         'view-RLVCQOIA0002',
//         'view-RLVCQOIA0003',
//         'view-RLVCQOIA0004',
//         'view-RLVCQOIA0005'
//     ])->plainTextToken;
    
//     return response()->json([
//         'token' => $token
//     ]);
// });

// Token generation route
Route::post('generate-tokens', function (Request $request) {
    // Get the user ID from the request
    $user = User::find($request->user_id);

    // Check if user exists
    if (!$user) {
        return response()->json(['message' => 'User not found'], 404);
    }

    // Define shop access based on the user's email
    $abilities = [];
    switch ($user->email) {
        case 'test@example.com':
            // Allow access to RLVS001 and RLVS002 for test@example.com
            $abilities = [
                'view-RLVS001',
                'view-RLVS002'
            ];
            break;
        case 'admin@admin.com':
            // Allow access to RLVS003 for admin@admin.com
            $abilities = [
                'view-RLVS003'
            ];
            break;
        default:
            return response()->json(['message' => 'No shops assigned for this user'], 403);
    }

    // Generate the token with specific shop-based abilities
    $token = $user->createToken('Shop Access Token', $abilities)->plainTextToken;

    // Return the token and its abilities
    return response()->json([
        'token' => $token,
        'abilities' => $abilities
    ]);
});


// Route::post('generate-tokens', function (Request $request) {
//     // Get the user ID from the request
//     $user = User::find($request->user_id);

//     // Check if user exists
//     if (!$user) {
//         return response()->json(['message' => 'User not found'], 404);
//     }

//     // Define collection access based on the user's email
//     $abilities = [];
//     switch ($user->email) {
//         case 'test@example.com':
//             $abilities = [
//                 'view-RLVCQOIA0001',
//                 'view-RLVCQOIA0002',
//                 'view-RLVCQOIA0003'
//             ];
//             break;
//         case 'admin@admin.com':
//             $abilities = [
//                 'view-RLVCQOIA0004',
//                 'view-RLVCQOIA0005'
//             ];
//             break;
//         default:
//             return response()->json(['message' => 'No collections assigned for this user'], 403);
//     }

//     // Generate the token with specific abilities
//     $token = $user->createToken('Collection Access Token', $abilities)->plainTextToken;

//     // Return the token and its abilities
//     return response()->json([
//         'token' => $token,
//         'abilities' => $abilities
//     ]);
// });

