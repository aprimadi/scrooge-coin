import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.Assert;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.InvalidKeyException;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MaxFeeTxHandlerTest {
    private static final int NUM_KEYS = 2;

    private static PublicKey[] publicKeys;
    private static PrivateKey[] privateKeys;

    @BeforeClass public static void beforeClass() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        publicKeys = new PublicKey[NUM_KEYS];
        privateKeys = new PrivateKey[NUM_KEYS];

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        keyGen.initialize(512, random);

        for (int i = 0; i < NUM_KEYS; ++i) {
            KeyPair pair = keyGen.generateKeyPair();
            publicKeys[i] = pair.getPublic();
            privateKeys[i] = pair.getPrivate();
        }
    }

    @Test public void testIsValidTxSuccess() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Initialize pool with one UTXO that belongs to address0 / scrooge {@code publicKeys[0]}
        UTXOPool pool = new UTXOPool();

        // Create initial transaction that creates 100 coin signed by scrooge {@code publicKeys[0]}
        Transaction transaction0 = new Transaction();
        transaction0.addInput(null, 0);
        transaction0.addOutput(100.0, publicKeys[0]);
        Transaction.Output out = transaction0.getOutput(0);
        transaction0.finalize();

        UTXO utxo = new UTXO(transaction0.getHash(), 0);
        pool.addUTXO(utxo, out);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(pool);

        // Create transaction that gives 1 coin to address1 {@code publicKeys[1]}
        Transaction transaction = new Transaction();
        transaction.addInput(transaction0.getHash(), 0);
        transaction.addOutput(1.0, publicKeys[1]);
        Transaction.Input input = transaction.getInput(0);

        // Address0 needs to sign it so that the transaction is valid
        byte[] inputDataToSign = transaction.getRawDataToSign(0);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKeys[0]);
        sig.update(inputDataToSign);
        byte[] signatureBytes = sig.sign();
        input.addSignature(signatureBytes);

        Assert.assertEquals(true, txHandler.isValidTx(transaction));
    }

    @Test public void testIsValidTx_Fail_UTXONotValid() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Initialize pool with one UTXO that belongs to address0 / scrooge {@code publicKeys[0]}
        UTXOPool pool = new UTXOPool();

        // Create initial transaction that creates 100 coin signed by scrooge {@code publicKeys[0]}
        Transaction transaction0 = new Transaction();
        transaction0.addInput(null, 0);
        transaction0.addOutput(100.0, publicKeys[0]);
        Transaction.Output out = transaction0.getOutput(0);
        transaction0.finalize();

        UTXO utxo = new UTXO(transaction0.getHash(), 0);
        pool.addUTXO(utxo, out);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(pool);

        // Create transaction that gives 1 coin to address1 {@code publicKeys[1]}
        Transaction transaction = new Transaction();
        transaction.addInput("SOME_INVALID_HASH".getBytes(), 0);
        transaction.addOutput(1.0, publicKeys[1]);
        Transaction.Input input = transaction.getInput(0);

        // Address0 needs to sign it so that the transaction is valid
        byte[] inputDataToSign = transaction.getRawDataToSign(0);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKeys[0]);
        sig.update(inputDataToSign);
        byte[] signatureBytes = sig.sign();
        input.addSignature(signatureBytes);

        Assert.assertEquals(false, txHandler.isValidTx(transaction));
    }

    @Test public void testIsValidTx_Fail_InputSignatureNotValid() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Initialize pool with one UTXO that belongs to address0 / scrooge {@code publicKeys[0]}
        UTXOPool pool = new UTXOPool();

        // Create initial transaction that creates 100 coin signed by scrooge {@code publicKeys[0]}
        Transaction transaction0 = new Transaction();
        transaction0.addInput(null, 0);
        transaction0.addOutput(100.0, publicKeys[0]);
        Transaction.Output out = transaction0.getOutput(0);
        transaction0.finalize();

        UTXO utxo = new UTXO(transaction0.getHash(), 0);
        pool.addUTXO(utxo, out);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(pool);

        // Create transaction that gives 1 coin to address1 {@code publicKeys[1]}
        Transaction transaction = new Transaction();
        transaction.addInput(transaction0.getHash(), 0);
        transaction.addOutput(1.0, publicKeys[1]);
        Transaction.Input input = transaction.getInput(0);

        // Address0 needs to sign it so that the transaction is valid, however
        // Address1 signs it instead of Address0
        byte[] inputDataToSign = transaction.getRawDataToSign(0);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKeys[1]);
        sig.update(inputDataToSign);
        byte[] signatureBytes = sig.sign();
        input.addSignature(signatureBytes);

        Assert.assertEquals(false, txHandler.isValidTx(transaction));
    }

    @Test public void testIsValidTx_Fail_InputSignatureIsEmpty() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Initialize pool with one UTXO that belongs to address0 / scrooge {@code publicKeys[0]}
        UTXOPool pool = new UTXOPool();

        // Create initial transaction that creates 100 coin signed by scrooge {@code publicKeys[0]}
        Transaction transaction0 = new Transaction();
        transaction0.addInput(null, 0);
        transaction0.addOutput(100.0, publicKeys[0]);
        Transaction.Output out = transaction0.getOutput(0);
        transaction0.finalize();

        UTXO utxo = new UTXO(transaction0.getHash(), 0);
        pool.addUTXO(utxo, out);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(pool);

        // Create transaction that gives 1 coin to address1 {@code publicKeys[1]}
        Transaction transaction = new Transaction();
        transaction.addInput(transaction0.getHash(), 0);
        transaction.addOutput(1.0, publicKeys[1]);
        Transaction.Input input = transaction.getInput(0);

        Assert.assertEquals(false, txHandler.isValidTx(transaction));
    }

    @Test public void testIsValidTx_Fail_OutputNegativeValue() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Initialize pool with one UTXO that belongs to address0 / scrooge {@code publicKeys[0]}
        UTXOPool pool = new UTXOPool();

        // Create initial transaction that creates 100 coin signed by scrooge {@code publicKeys[0]}
        Transaction transaction0 = new Transaction();
        transaction0.addInput(null, 0);
        transaction0.addOutput(100.0, publicKeys[0]);
        Transaction.Output out = transaction0.getOutput(0);
        transaction0.finalize();

        UTXO utxo = new UTXO(transaction0.getHash(), 0);
        pool.addUTXO(utxo, out);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(pool);

        // Create transaction that gives 1 coin to address1 {@code publicKeys[1]}
        Transaction transaction = new Transaction();
        transaction.addInput(transaction0.getHash(), 0);
        transaction.addOutput(-0.1, publicKeys[1]);
        Transaction.Input input = transaction.getInput(0);

        // Address0 needs to sign it so that the transaction is valid
        byte[] inputDataToSign = transaction.getRawDataToSign(0);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKeys[0]);
        sig.update(inputDataToSign);
        byte[] signatureBytes = sig.sign();
        input.addSignature(signatureBytes);

        Assert.assertEquals(false, txHandler.isValidTx(transaction));
    }

    @Test public void testIsValidTx_Fail_UTXOUsedMultipleTimes() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Initialize pool with one UTXO that belongs to address0 / scrooge {@code publicKeys[0]}
        UTXOPool pool = new UTXOPool();

        // Create initial transaction that creates 100 coin signed by scrooge {@code publicKeys[0]}
        Transaction transaction0 = new Transaction();
        transaction0.addInput(null, 0);
        transaction0.addOutput(100.0, publicKeys[0]);
        Transaction.Output out = transaction0.getOutput(0);
        transaction0.finalize();

        UTXO utxo = new UTXO(transaction0.getHash(), 0);
        pool.addUTXO(utxo, out);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(pool);

        // Create transaction that gives 1 coin to address1 {@code publicKeys[1]}
        Transaction transaction = new Transaction();
        transaction.addInput(transaction0.getHash(), 0);
        transaction.addInput(transaction0.getHash(), 0);
        transaction.addOutput(1.0, publicKeys[1]);
        Transaction.Input input1 = transaction.getInput(0);
        Transaction.Input input2 = transaction.getInput(1);

        // Address0 needs to sign it so that the transaction is valid
        byte[] inputDataToSign1 = transaction.getRawDataToSign(0);
        Signature sig1 = Signature.getInstance("SHA256withRSA");
        sig1.initSign(privateKeys[0]);
        sig1.update(inputDataToSign1);
        byte[] signatureBytes1 = sig1.sign();
        input1.addSignature(signatureBytes1);

        byte[] inputDataToSign2 = transaction.getRawDataToSign(1);
        Signature sig2 = Signature.getInstance("SHA256withRSA");
        sig2.initSign(privateKeys[0]);
        sig2.update(inputDataToSign2);
        byte[] signatureBytes2 = sig2.sign();
        input2.addSignature(signatureBytes2);

        Assert.assertEquals(false, txHandler.isValidTx(transaction));
    }

    @Test public void testIsValidTx_Fail_OutputValuesExceedsInputs() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Initialize pool with one UTXO that belongs to address0 / scrooge {@code publicKeys[0]}
        UTXOPool pool = new UTXOPool();

        // Create initial transaction that creates 100 coin signed by scrooge {@code publicKeys[0]}
        Transaction transaction0 = new Transaction();
        transaction0.addInput(null, 0);
        transaction0.addOutput(100.0, publicKeys[0]);
        Transaction.Output out = transaction0.getOutput(0);
        transaction0.finalize();

        UTXO utxo = new UTXO(transaction0.getHash(), 0);
        pool.addUTXO(utxo, out);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(pool);

        // Create transaction that gives 1 coin to address1 {@code publicKeys[1]}
        Transaction transaction = new Transaction();
        transaction.addInput(transaction0.getHash(), 0);
        transaction.addOutput(50.0, publicKeys[1]);
        transaction.addOutput(70.0, publicKeys[1]);
        Transaction.Input input1 = transaction.getInput(0);

        // Address0 needs to sign it so that the transaction is valid
        byte[] inputDataToSign1 = transaction.getRawDataToSign(0);
        Signature sig1 = Signature.getInstance("SHA256withRSA");
        sig1.initSign(privateKeys[0]);
        sig1.update(inputDataToSign1);
        byte[] signatureBytes1 = sig1.sign();
        input1.addSignature(signatureBytes1);

        Assert.assertEquals(false, txHandler.isValidTx(transaction));
    }

    @Test public void testHandleTxs_Success() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Initialize pool with one UTXO that belongs to address0 / scrooge {@code publicKeys[0]}
        UTXOPool pool = new UTXOPool();

        // Create initial transaction that creates 100 coin signed by scrooge {@code publicKeys[0]}
        Transaction transaction0 = new Transaction();
        transaction0.addInput(null, 0);
        transaction0.addOutput(100.0, publicKeys[0]);
        Transaction.Output out = transaction0.getOutput(0);
        transaction0.finalize();

        UTXO utxo = new UTXO(transaction0.getHash(), 0);
        pool.addUTXO(utxo, out);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(pool);

        // Create transaction that gives 1 coin to address1 {@code publicKeys[1]}
        Transaction transaction = new Transaction();
        transaction.addInput(transaction0.getHash(), 0);
        transaction.addOutput(100.0, publicKeys[1]);
        Transaction.Input input1 = transaction.getInput(0);

        // Address0 needs to sign it so that the transaction is valid
        byte[] inputDataToSign1 = transaction.getRawDataToSign(0);
        Signature sig1 = Signature.getInstance("SHA256withRSA");
        sig1.initSign(privateKeys[0]);
        sig1.update(inputDataToSign1);
        byte[] signatureBytes1 = sig1.sign();
        input1.addSignature(signatureBytes1);

        Transaction[] txs = new Transaction[1];
        txs[0] = transaction;

        Assert.assertArrayEquals(txs, txHandler.handleTxs(txs));
    }

    @Test public void testHandleTxs_DoubleSpending() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Initialize pool with one UTXO that belongs to address0 / scrooge {@code publicKeys[0]}
        UTXOPool pool = new UTXOPool();

        // Create initial transaction that creates 100 coin signed by scrooge {@code publicKeys[0]}
        Transaction transaction0 = new Transaction();
        transaction0.addInput(null, 0);
        transaction0.addOutput(100.0, publicKeys[0]);
        Transaction.Output out = transaction0.getOutput(0);
        transaction0.finalize();

        UTXO utxo = new UTXO(transaction0.getHash(), 0);
        pool.addUTXO(utxo, out);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(pool);

        // Create transaction that gives 1 coin to address1 {@code publicKeys[1]}
        Transaction transaction = new Transaction();
        transaction.addInput(transaction0.getHash(), 0);
        transaction.addOutput(100.0, publicKeys[1]);
        Transaction.Input input1 = transaction.getInput(0);

        // Address0 needs to sign it so that the transaction is valid
        byte[] inputDataToSign1 = transaction.getRawDataToSign(0);
        Signature sig1 = Signature.getInstance("SHA256withRSA");
        sig1.initSign(privateKeys[0]);
        sig1.update(inputDataToSign1);
        byte[] signatureBytes1 = sig1.sign();
        input1.addSignature(signatureBytes1);

        Transaction[] txs = new Transaction[1];
        txs[0] = transaction;

        Assert.assertArrayEquals(txs, txHandler.handleTxs(txs));


        Transaction transaction2 = new Transaction();
        transaction2.addInput(transaction0.getHash(), 0);
        transaction2.addOutput(100.0, publicKeys[1]);
        Transaction.Input t2input = transaction2.getInput(0);

        // Address0 needs to sign it so that the transaction is valid
        byte[] t2inputDataToSign = transaction2.getRawDataToSign(0);
        Signature t2Sig = Signature.getInstance("SHA256withRSA");
        t2Sig.initSign(privateKeys[0]);
        t2Sig.update(inputDataToSign1);
        byte[] t2SignatureBytes = t2Sig.sign();
        t2input.addSignature(t2SignatureBytes);

        Transaction[] txs2 = new Transaction[1];
        txs2[0] = transaction;

        Assert.assertArrayEquals(new Transaction[0], txHandler.handleTxs(txs2));
    }

    @Test public void testHandleTxs_MaxFee() {
        // Initialize pool with one UTXO that belongs to address0 / scrooge {@code publicKeys[0]}
        UTXOPool pool = new UTXOPool();

        // Create initial transaction that creates 100 coin signed by scrooge {@code publicKeys[0]}
        Transaction transaction0 = new Transaction();
        transaction0.addInput(null, 0);
        transaction0.addOutput(100.0, publicKeys[0]);
        transaction0.addOutput(100.0, publicKeys[0]);
        Transaction.Output out1 = transaction0.getOutput(0);
        Transaction.Output out2 = transaction0.getOutput(1);
        transaction0.finalize();

        UTXO utxo1 = new UTXO(transaction0.getHash(), 0);
        UTXO utxo2 = new UTXO(transaction0.getHash(), 1);
        pool.addUTXO(utxo1, out1);
        pool.addUTXO(utxo2, out2);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(pool);

        // Create 3 transactions with the following fee: 8 (t1), 5 (t2), 14 (t3)
        // t1 and t3 conflict so the maximum fee should be t2 + t3 = 19
        // Create transaction that gives 1 coin to address1 {@code publicKeys[1]}
        Transaction t1 = new Transaction();
        t1.addInput(transaction0.getHash(), 0);
        t1.addOutput(92.0, publicKeys[1]);
        Transaction.Input t1input = t1.getInput(0);
        byte[] t1inputData = t1.getRawDataToSign(0);
        signInput(t1input, t1inputData, privateKeys[0]);

        Transaction t2 = new Transaction();
        t2.addInput(transaction0.getHash(), 1);
        t2.addOutput(95.0, publicKeys[1]);
        Transaction.Input t2input = t2.getInput(0);
        byte[] t2inputData = t2.getRawDataToSign(0);
        signInput(t2input, t2inputData, privateKeys[0]);

        Transaction t3 = new Transaction();
        t3.addInput(transaction0.getHash(), 0);
        t3.addOutput(86.0, publicKeys[1]);
        Transaction.Input t3input = t3.getInput(0);
        byte[] t3inputData = t3.getRawDataToSign(0);
        signInput(t3input, t3inputData, privateKeys[0]);

        Transaction[] txs = new Transaction[3];
        txs[0] = t1;
        txs[1] = t2;
        txs[2] = t3;

        Transaction[] etxs = new Transaction[2];
        etxs[0] = t3;
        etxs[1] = t2;

        Assert.assertArrayEquals(etxs, txHandler.handleTxs(txs));
    }


    private void signInput(Transaction.Input input, byte[] rawData, PrivateKey privKey) {
        Signature sig = null;
        byte[] signatureBytes = null;

        try {
            sig = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            sig.initSign(privKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            sig.update(rawData);
            signatureBytes = sig.sign();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        input.addSignature(signatureBytes);
    }
}
