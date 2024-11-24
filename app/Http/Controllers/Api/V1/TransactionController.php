<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\Transaction;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class TransactionController extends Controller
{
    // GET /api/transactions
    public function index()
    {
        return response()->json(Transaction::all(), 200);
    }

    // POST /api/transactions
    public function store(Request $request)
    {
        // Validate the request
        $validator = Validator::make($request->all(), [
            'code' => 'required|string|max:16|unique:transactions,code',
            'status' => 'required|in:paid,unpaid,expired',
            'amount' => 'required|numeric|min:0',
            'payment_description' => 'required|string|max:255',
            'payment_description2' => 'nullable|string|max:255', // Optional field
            'due_date' => 'required|date',
            'payer_name' => 'required|string|max:255',
            'payer_email' => 'required|email|unique:transactions,payer_email',
            'payer_phone' => 'required|string|max:20',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'errors' => $validator->errors(),
            ], 400);
        }

        // Create a new transaction
        $transaction = Transaction::create([
            'code' => $request->code,
            'status' => $request->status,
            'amount' => $request->amount,
            'payment_description' => $request->payment_description,
            'payment_description2' => $request->payment_description2, // Optional
            'due_date' => $request->due_date,
            'payer_name' => $request->payer_name,
            'payer_email' => $request->payer_email,
            'payer_phone' => $request->payer_phone,
        ]);

        return response()->json([
            'status' => 'success',
            'transaction' => $transaction,
        ], 201);
    }

    // GET /api/transactions/{id}
    public function show($id)
    {
        $transaction = Transaction::find($id);

        if (!$transaction) {
            return response()->json(['message' => 'Transaction not found'], 404);
        }

        return response()->json($transaction, 200);
    }

    // PUT /api/transactions/{id}
    public function update(Request $request, $id)
    {
        $transaction = Transaction::find($id);

        if (!$transaction) {
            return response()->json(['message' => 'Transaction not found'], 404);
        }

        $validated = $request->validate([
            'code' => 'sometimes|required|string|max:255',
            'status' => 'sometimes|required|in:paid,unpaid,expired',
            'amount' => 'sometimes|required|numeric',
            'payment_description' => 'sometimes|required|string',
            'due_date' => 'sometimes|required|date',
            'payer_name' => 'sometimes|required|string',
            'payer_email' => 'sometimes|required|email',
            'payer_phone' => 'sometimes|required|string|max:15',
        ]);

        $transaction->update($validated);

        return response()->json($transaction, 200);
    }

    // DELETE /api/transactions/{id}
    public function destroy($id)
    {
        $transaction = Transaction::find($id);

        if (!$transaction) {
            return response()->json(['message' => 'Transaction not found'], 404);
        }

        $transaction->delete();

        return response()->json(['message' => 'Transaction deleted'], 200);
    }
}
