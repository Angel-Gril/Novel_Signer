import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Looper;
import java.io.FileInputStream;
import java.security.MessageDigest;
import org.json.JSONArray;
import org.json.JSONObject;

/** Read installed package identity through Android's package manager as shell. */
public final class Vm9PackageIdentity {
    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte value : bytes) out.append(String.format("%02x", value & 255));
        return out.toString();
    }

    private static JSONArray signatures(Signature[] signatures) throws Exception {
        JSONArray rows = new JSONArray();
        if (signatures == null) return rows;
        for (Signature signature : signatures) {
            byte[] der = signature.toByteArray();
            JSONObject row = new JSONObject();
            row.put("length", der.length);
            row.put("sha256", hex(MessageDigest.getInstance("SHA-256").digest(der)));
            rows.put(row);
        }
        return rows;
    }

    private static String apkDigest(String path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream input = new FileInputStream(path)) {
            byte[] buffer = new byte[65536];
            int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return hex(digest.digest());
    }

    private static void probe(String[] args) throws Exception {
        if (args.length != 1 || !args[0].matches("(?:android|[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+)")) {
            throw new IllegalArgumentException("one explicit package name is required");
        }
        Looper.prepareMainLooper();
        Class<?> activityThread = Class.forName("android.app.ActivityThread");
        Object thread = activityThread.getMethod("systemMain").invoke(null);
        Context context = (Context) activityThread.getMethod("getSystemContext").invoke(thread);
        PackageManager manager = context.getPackageManager();
        PackageInfo legacy = manager.getPackageInfo(args[0], PackageManager.GET_SIGNATURES);
        JSONObject result = new JSONObject();
        result.put("event", "package_identity");
        result.put("package", legacy.packageName);
        result.put("sdk", Build.VERSION.SDK_INT);
        result.put("version_code", Build.VERSION.SDK_INT >= 28 ? legacy.getLongVersionCode() : legacy.versionCode);
        result.put("version_name", legacy.versionName);
        result.put("debuggable", (legacy.applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
        result.put("apk_sha256", apkDigest(legacy.applicationInfo.sourceDir));
        result.put("legacy_signatures", signatures(legacy.signatures));
        if (Build.VERSION.SDK_INT >= 28) {
            PackageInfo modern = manager.getPackageInfo(args[0], PackageManager.GET_SIGNING_CERTIFICATES);
            result.put("current_signers", signatures(modern.signingInfo.getApkContentsSigners()));
            result.put("signing_history", signatures(modern.signingInfo.getSigningCertificateHistory()));
        }
        result.put("target_process_instrumented", false);
        System.out.println(result.toString());
    }

    public static void main(String[] args) throws Exception {
        int status = 0;
        try {
            probe(args);
        } catch (Exception error) {
            Throwable cause = error;
            while (cause.getCause() != null) cause = cause.getCause();
            JSONObject result = new JSONObject();
            result.put("event", "package_identity_error");
            result.put("error_class", cause.getClass().getName());
            System.err.println(result.toString());
            status = 1;
        }
        // ActivityThread creates system threads; this shell helper must not keep running.
        System.exit(status);
    }
}
