<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log; // Logging added

class AuthController extends Controller
{
    // Login function that generate new token everytime user login
    // public function login(Request $request)
    // {
    //     $request->validate([
    //         'email' => 'required|email',
    //         'password' => 'required',
    //     ]);

    //     if (!Auth::attempt($request->only('email', 'password'))) {
    //         return response()->json([
    //             'message' => 'Invalid login credentials',
    //         ], 401);
    //     }

    //     $user = User::where('email', $request->email)->firstOrFail();

    //     // Generate token
    //     $token = $user->createToken('API Token')->plainTextToken;

    //     return response()->json([
    //         'token' => $token,
    //         'message' => 'Login successful'
    //     ], 200);
    // }


    // Login function that uses the same token each time the user logs in
    public function webLogin(Request $request)
    {
        // Validate the incoming request
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        // Log the login attempt
        Log::info('Login attempt:', ['email' => $request->email]);

        // Attempt to authenticate the user
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                'message' => 'Invalid login credentials',
            ], 401);
        }

        // Retrieve the authenticated user
        $user = User::where('email', $request->email)->firstOrFail();

        // Assign abilities based on the user’s email
        $abilities = $this->getUserAbilities($user);

        // Check if the user already has a token
        $existingToken = $user->tokens()->where('name', 'API Token')->first();

        if ($existingToken) {
            // Delete the existing token
            $existingToken->delete();
        }

        // Create a new token with updated abilities (shop codes)
        $token = $user->createToken('API Token', $abilities)->plainTextToken;

        // Log the generated token and abilities
        Log::info('Generated token:', ['token' => $token, 'abilities' => $abilities]);

        return response()->json([
            'token' => $token,
            'message' => 'Login successful',
            'abilities' => $abilities
        ], 200);
    }
    
    // Mobile Login function using Firebase token authentication
    public function mobileLogin(Request $request)
    {
        $firebaseToken = $request->input('firebase_token');

        // Define the Firebase token verification URL
        $url = 'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' . env('FIREBASE_WEB_API_KEY');

        // Make a POST request to the Firebase API
        $response = Http::post($url, [
            'idToken' => $firebaseToken,
        ]);

        // Log the response for debugging
        Log::info('Firebase token verification response:', $response->json());

        // Check the response from Firebase
        if ($response->successful()) {
            // Extract user information from the response
            $userData = $response->json();

            // Ensure users array is not empty
            if (empty($userData['users'])) {
                return response()->json(['error' => 'No user data returned from Firebase'], 401);
            }

            // Get the email from the response
            $email = $userData['users'][0]['email'];

            // Check if the user exists in your system
            $user = User::where('email', $email)->first();

            // If user does not exist, consider creating a new one
            if (!$user) {
                $user = User::create(['email' => $email]);
                // Optionally send a welcome email or perform other actions
            }

            // Check if the email is verified
            if (!$user->email_verified_at) {
                return response()->json(['error' => 'Email not verified'], 403);
            }

            // Check if the user already has an active, non-expired token
            $existingToken = $user->tokens()
                ->where('name', 'Collection Access Token')
                ->where(function($query) {
                    $query->whereNull('expires_at')->orWhere('expires_at', '>', now());
                })
                ->first();

            if ($existingToken) {
                // Return the actual token string and its abilities if the token exists and is still valid
                return response()->json([
                    'token' => $existingToken->token,
                    'abilities' => $this->getUserAbilities($user),
                ]);
            }

            // Generate a new token with specific abilities if no active, non-expired token exists
            $newToken = $user->createToken('Collection Access Token', $this->getUserAbilities($user))->plainTextToken;

            // Return the new token and its abilities
            return response()->json([
                'token' => $newToken,
                'abilities' => $this->getUserAbilities($user),
            ]);
        } else {
            // Log the error from Firebase
            Log::error('Invalid Firebase token response:', $response->json());
            return response()->json(['error' => 'Invalid Firebase token'], 401);
        }
    }

    // Method to get user abilities based on email
    private function getUserAbilities(User $user)
    {
        $abilities = [];
        switch ($user->email) {
            case 'test@example.com':
                $abilities = [
                    'view-RLVS001',
                    'view-RLVS002'
                ];
                break;
            case 'admin@admin.com':
                $abilities = [
                    'view-RLVS003'
                ];
                break;
            default:
                return null; // No abilities defined for other users
        }
        return $abilities;
    }
}
