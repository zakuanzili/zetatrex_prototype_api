<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Billing;
use App\Models\Collection;
use App\Models\User;
use Google\Client;
use GuzzleHttp\Client as GuzzleHttpClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log; // Logging added
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Http;

class BillingController extends Controller
{
    // Fetch all billings
    public function index(Request $request)
    {
        // Ensure the user is authenticated
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        // Check if the user is authorized to view billings
        if (Gate::denies('view-billings')) {
            
            Log::info('Unauthorized to view this collection billing');
            return response()->json(['message' => 'Unauthorized to view this collection billing'], 403);
        }

        // Retrieve all billings from the database
        $billings = Billing::all();
        Log::info('All Billings Retrieved: ', ['count' => $billings->count()]);

        return response()->json($billings); // Return as JSON response
    }

    // Fetch a specific billing by its code
    public function show($code, Request $request)
    {
        // Ensure the user is authenticated
        if (!$request->user()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        // Check if the user is authorized to view this specific billing
        if (Gate::denies('view-billing', $code)) {
            return response()->json(['message' => 'Unauthorized to view this billing'], 403);
        }

        // Find the billing by code
        $billing = Billing::where('code', $code)->first();

        if (!$billing) {
            Log::error('Billing Not Found: ', ['code' => $code]);
            return response()->json(['message' => 'Billing not found'], 404);
        }

        Log::info('Billing Retrieved: ', ['code' => $code]);
        return response()->json($billing); // Return the billing record
    }

    // Create a new billing record
    // public function store(Request $request)
    // {
    //     $request->validate([
    //         'code' => 'required|string|size:18|unique:billings,code',
    //         'belong_to_collection' => 'required|string',
    //         'status' => 'required|string',
    //         'amount' => 'required|numeric',
    //         'payment_description' => 'nullable|string',
    //         'payment_description2' => 'nullable|string',
    //         'due_date' => 'required|date',
    //         'payer_name' => 'required|string',
    //         'payer_email' => 'required|email',
    //         'payer_phone' => 'required|string',
    //         'payment_method' => 'required|string|in:OBW,MPGS,QR Pay',
    //     ]);

    //     $billing = Billing::create($request->all());  // Create a new billing record
    //     Log::info('Billing Created: ', ['code' => $billing->code]);

    //     return response()->json($billing, 201);  // Return the created billing as JSON
    // }

    // // Create a new billing record associated with a specific collection
    // public function createBillingForCollection(Request $request, $collectionCode)
    // {
    //     // Check if the collection exists
    //     $collection = Collection::where('code', $collectionCode)->first();

    //     if (!$collection) {
    //         Log::error('Collection Not Found: ', ['collection_code' => $collectionCode]);
    //         return response()->json(['message' => 'Collection not found'], 404);
    //     }

    //     // Validate the billing data
    //     $request->validate([
    //         'code' => 'required|string|size:18|unique:billings,code',
    //         'status' => 'required|string',
    //         'amount' => 'required|numeric',
    //         'payment_description' => 'nullable|string',
    //         'payment_description2' => 'nullable|string',
    //         'due_date' => 'required|date',
    //         'payer_name' => 'required|string',
    //         'payer_email' => 'required|email',
    //         'payer_phone' => 'required|string',
    //         'payment_method' => 'required|string|in:OBW,MPGS,QR Pay',
    //     ]);

    //     // Create the billing record with the collection's code
    //     $billing = Billing::create([
    //         'code' => $request->input('code'),
    //         'belong_to_collection' => $collectionCode,  // Associate with the collection
    //         'status' => $request->input('status'),
    //         'amount' => $request->input('amount'),
    //         'payment_description' => $request->input('payment_description'),
    //         'payment_description2' => $request->input('payment_description2'),
    //         'due_date' => $request->input('due_date'),
    //         'payer_name' => $request->input('payer_name'),
    //         'payer_email' => $request->input('payer_email'),
    //         'payer_phone' => $request->input('payer_phone'),
    //         'payment_method' => $request->input('payment_method'),
    //     ]);

    //     Log::info('Billing Created for Collection: ', ['code' => $billing->code, 'collection_code' => $collectionCode]);

    //     return response()->json($billing, 201); // Return the created billing as JSON
    // }

    // Update an existing billing record
    public function update(Request $request, $code)
    {
        $billing = Billing::where('code', $code)->first();

        if (!$billing) {
            Log::error('Billing Not Found: ', ['code' => $code]);
            return response()->json(['message' => 'Billing not found'], 404);
        }

        $request->validate([
            'status' => 'required|in:paid,unpaid,expired',
            'amount' => 'numeric',
            'payment_description' => 'nullable|string',
            'payment_description2' => 'nullable|string',
            'due_date' => 'date',
            'payer_name' => 'string',
            'payer_email' => 'email',
            'payer_phone' => 'string',
            'payment_method' => 'required|in:OBW,MPGS,QR Pay',
        ]);
        
        $billing->update($request->all());  // Update the billing record
        Log::info('Billing Updated: ', ['code' => $code]);

        return response()->json($billing);  // Return the updated billing as JSON
    }

    // Create a new billing record for a collection
    public function createBillingForCollection(Request $request, $collectionCode)
    {
        $collection = Collection::where('code', $collectionCode)->first();

        if (!$collection) {
            Log::error('Collection Not Found', ['collection_code' => $collectionCode]);
            return response()->json(['message' => 'Collection not found'], 404);
        }

        $request->validate([
            'code' => 'required|string|size:18|unique:billings,code',
            'status' => 'required|string',
            'amount' => 'required|numeric',
            'payment_description' => 'nullable|string',
            'payment_description2' => 'nullable|string',
            'due_date' => 'required|date',
            'payer_name' => 'required|string',
            'payer_email' => 'required|email',
            'payer_phone' => 'required|string',
            'payment_method' => 'required|string|in:OBW,MPGS,QR Pay',
        ]);

        $billing = Billing::create([
            'code' => $request->input('code'),
            'belong_to_collection' => $collectionCode,
            'status' => $request->input('status'),
            'amount' => $request->input('amount'),
            'payment_description' => $request->input('payment_description'),
            'payment_description2' => $request->input('payment_description2'),
            'due_date' => $request->input('due_date'),
            'payer_name' => $request->input('payer_name'),
            'payer_email' => $request->input('payer_email'),
            'payer_phone' => $request->input('payer_phone'),
            'payment_method' => $request->input('payment_method'),
        ]);

        Log::info('Billing Created', ['code' => $billing->code]);

        // Send FCM Notification if user exists
        $user = User::where('email', 'test@example.com')->first();
        if ($user && $user->fcm_token) {
            $title = "New Payment";

            // Format the amount to two decimal places
            $formattedAmount = number_format($billing->amount, 2);

            $body = "You have received RM" . $formattedAmount . " via QR PAY";
            $this->sendFCMNotification($title, $body, $billing->amount, $user->id);
        } else {
            Log::error('FCM Notification Failed: User or FCM Token not found');
        }

        return response()->json($billing, 201);
    }

    // Send FCM Notification
    public function sendFCMNotification($title, $body, $amount, $userId)
    {
        $accessToken = $this->getFirebaseAccessToken();
        if (!$accessToken) {
            Log::error('FCM Notification Failed: Access token not available');
            return;
        }

        $user = User::find($userId);
        if (!$user || !$user->fcm_token) {
            Log::error('FCM Notification Failed: User or FCM token not found');
            return;
        }

        $url = "https://fcm.googleapis.com/v1/projects/nexgen-client-app/messages:send";
        $notificationData = [
            'message' => [
                'token' => $user->fcm_token,
                'notification' => [
                    'title' => $title,
                    'body' => $body,
                ],
                'data' => [
                    'amount' => (string) $amount, // Ensure 'amount' is a string
                    'click_action' => 'FLUTTER_NOTIFICATION_CLICK',
                ],
            ],
        ];

        $client = new GuzzleHttpClient();
        try {
            $client->post($url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $accessToken,
                    'Content-Type' => 'application/json',
                ],
                'json' => $notificationData,
            ]);
            Log::info('FCM Notification Sent');
        } catch (\Exception $e) {
            Log::error('FCM Notification Failed', ['error' => $e->getMessage()]);
        }
    }

    // Get Firebase Access Token
    public function getFirebaseAccessToken()
    {
        // Retrieve Firebase credentials from environment variables
        $clientEmail = env('FIREBASE_CLIENT_EMAIL');
        $privateKey = str_replace("\\n", "\n", env('FIREBASE_PRIVATE_KEY')); // Ensure newlines are handled
        $tokenUri = env('FIREBASE_TOKEN_URI');

        if (!$clientEmail || !$privateKey || !$tokenUri) {
            Log::error('Firebase credentials are missing in environment variables.');
            return null;
        }

        // Prepare JWT components
        $jwtHeader = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
        $jwtPayload = base64_encode(json_encode([
            'iss' => $clientEmail,
            'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
            'aud' => $tokenUri,
            'exp' => time() + 3600,
            'iat' => time(),
        ]));

        $signature = '';
        openssl_sign("$jwtHeader.$jwtPayload", $signature, $privateKey, 'sha256');
        $jwt = "$jwtHeader.$jwtPayload." . base64_encode($signature);

        // Request the access token
        $response = Http::post($tokenUri, [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $jwt,
        ]);

        // Check and return the token
        if ($response->successful()) {
            return $response->json('access_token');
        }

        Log::error('Failed to retrieve Firebase Access Token', ['response' => $response->json()]);
        return null;
    }

    // Get Firebase Access Token

    // public function getFirebaseAccessToken()
    // {
    //     $serviceAccountJson = 'firebase/firebase.json';
    //     if (!file_exists($serviceAccountJson)) {
    //         Log::error('Firebase Service Account JSON Not Found');
    //         return null;
    //     }

    //     $serviceAccount = json_decode(file_get_contents($serviceAccountJson), true);
    //     $clientEmail = $serviceAccount['client_email'];
    //     $privateKey = $serviceAccount['private_key'];
    //     $tokenUri = $serviceAccount['token_uri'];

    //     $jwtHeader = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
    //     $jwtPayload = base64_encode(json_encode([
    //         'iss' => $clientEmail,
    //         'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
    //         'aud' => $tokenUri,
    //         'exp' => time() + 3600,
    //         'iat' => time(),
    //     ]));

    //     $signature = '';
    //     openssl_sign("$jwtHeader.$jwtPayload", $signature, $privateKey, 'sha256');
    //     $jwt = "$jwtHeader.$jwtPayload." . base64_encode($signature);

    //     $response = Http::post($tokenUri, [
    //         'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    //         'assertion' => $jwt,
    //     ]);

    //     return $response->json('access_token') ?? null;
    // }

    // private function encodeJWT($header, $payload, $privateKey)
    // {
    //     // Encode the header
    //     $encodedHeader = base64_encode(json_encode($header));

    //     // Encode the payload
    //     $encodedPayload = base64_encode(json_encode($payload));

    //     // Create the signature
    //     $signatureInput = $encodedHeader . '.' . $encodedPayload;
    //     $signature = '';
        
    //     // Correct usage of OPENSSL_ALGO_RS256 constant (no namespace)
    //     // openssl_sign($signatureInput, $signature, $privateKey, OPENSSL_ALGO_RS256);
    //     openssl_sign($signatureInput, $signature, $privateKey);
        
    //     // Base64-encode the signature
    //     $encodedSignature = base64_encode($signature);

    //     // Return the full JWT token
    //     return $signatureInput . '.' . $encodedSignature;
    // }
}
