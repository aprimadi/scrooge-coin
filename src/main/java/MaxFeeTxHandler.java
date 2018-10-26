import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;

public class MaxFeeTxHandler {
    private UTXOPool pool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public MaxFeeTxHandler(UTXOPool utxoPool) {
        pool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        // Check if all outputs claimed by {@code tx} are in the current UTXO pool
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            if (!pool.contains(utxo)) {
                return false;
            }
        }

        // Check if the signatures on each input of {@code tx} are valid
        for (int i = 0; i < tx.numInputs(); ++i) {
            byte[] data = tx.getRawDataToSign(i);
            Transaction.Input in = tx.getInput(i);
            if (in.signature == null) {
                return false;
            }
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            Transaction.Output out = pool.getTxOutput(utxo);
            if (!Crypto.verifySignature(out.address, data, in.signature)) {
                return false;
            }
        }

        // No UTXO is claimed multiple times by {@code tx}
        Set<Integer> hashCodes = new HashSet<Integer>();
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            if (hashCodes.contains(utxo.hashCode())) {
                return false;
            }
            hashCodes.add(utxo.hashCode());
        }

        // All of {@code tx}s output values are non-negative
        for (int i = 0; i < tx.numOutputs(); i++) {
            Transaction.Output out = tx.getOutput(i);
            if (out.value < 0) {
                return false;
            }
        }

        // the sum of {@code tx}s input values is greater than or equal to the
        // sum of its output values; and false otherwise.
        double outputSum = 0;
        double inputSum = 0;
        for (int i = 0; i < tx.numOutputs(); ++i) {
            Transaction.Output out = tx.getOutput(i);
            outputSum += out.value;
        }
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            Transaction.Output out = pool.getTxOutput(utxo);
            inputSum += out.value;
        }
        if (inputSum < outputSum) {
            return false;
        }

        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> transactions = new ArrayList<Transaction>();

        // We use an approximation algorithm for multidimensional knapsack
        // problem, assuming that the transactions are sparse (in a sense that
        // it rarely uses the same UTXO twice for different transactions).

        // So, we first sort the transactions in descending order and accept
        // transactions that has non-conflicting UTXO only.

        ArrayList<Transaction> _txs = new ArrayList<Transaction>();
        // Filter non valid transactions
        for (int i = 0; i < possibleTxs.length; ++i) {
            if (isValidTx(possibleTxs[i])) {
                _txs.add(possibleTxs[i]);
            }
        }
        Transaction[] txs = new Transaction[_txs.size()];
        for (int i = 0; i < _txs.size(); ++i) {
            txs[i] = _txs.get(i);
        }


        Comparator<Transaction> transactionComparator = new Comparator<Transaction>() {
            @Override
            public int compare(Transaction t1, Transaction t2) {
                double f1 = transactionFee(t1);
                double f2 = transactionFee(t2);
                if (f1 > f2) {
                    return -1;
                } else if (f1 < f2) {
                    return 1;
                } else {
                    return 0;
                }
            }
        };
        Arrays.sort(txs, transactionComparator);

        Set<UTXO> utxos = new HashSet<UTXO>();

        for (int i = 0; i < txs.length; ++i) {
            if (!containDuplicateUTXOs(utxos, txs[i])) {
                transactions.add(txs[i]);
                acceptTransaction(txs[i]);
                insertUTXOs(utxos, txs[i]);
            }
        }

        Transaction[] _transactions = new Transaction[transactions.size()];
        for (int i = 0; i < transactions.size(); ++i) {
            _transactions[i] = transactions.get(i);
        }
        return _transactions;
    }

    private void acceptTransaction(Transaction tx) {
        tx.finalize();

        // Remove used coins from UTXO
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            pool.removeUTXO(utxo);
        }

        // Add outputs to UTXOPool
        for (int i = 0; i < tx.numOutputs(); ++i) {
          Transaction.Output out = tx.getOutput(i);
          UTXO utxo = new UTXO(tx.getHash(), i);
          pool.addUTXO(utxo, out);
        }
    }

    private double transactionFee(Transaction tx) {
        double outputSum = 0;
        double inputSum = 0;
        for (int i = 0; i < tx.numOutputs(); ++i) {
            Transaction.Output out = tx.getOutput(i);
            outputSum += out.value;
        }
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            Transaction.Output out = pool.getTxOutput(utxo);
            inputSum += out.value;
        }
        return Math.max(inputSum - outputSum, 0);
    }

    private static boolean containDuplicateUTXOs(Set<UTXO> utxos, Transaction tx) {
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            if (utxos.contains(utxo)) {
                return true;
            }
        }
        return false;
    }

    private static void insertUTXOs(Set<UTXO> utxos, Transaction tx) {
        for (int i = 0; i < tx.numInputs(); ++i) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            utxos.add(utxo);
        }
    }
}
