package digital.filip.mytown;

import com.destroystokyo.paper.profile.PlayerProfile;
import io.papermc.paper.command.brigadier.BasicCommand;
import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.connection.PlayerCommonConnection;
import io.papermc.paper.connection.PlayerConfigurationConnection;
import io.papermc.paper.connection.PlayerConnection;
import io.papermc.paper.connection.PlayerLoginConnection;
import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.dialog.DialogResponseView;
import io.papermc.paper.event.connection.PlayerConnectionValidateLoginEvent;
import io.papermc.paper.event.connection.configuration.AsyncPlayerConnectionConfigureEvent;
import io.papermc.paper.event.player.PlayerCustomClickEvent;
import io.papermc.paper.plugin.lifecycle.event.types.LifecycleEvents;
import io.papermc.paper.registry.data.dialog.ActionButton;
import io.papermc.paper.registry.data.dialog.DialogBase;
import io.papermc.paper.registry.data.dialog.action.DialogAction;
import io.papermc.paper.registry.data.dialog.body.DialogBody;
import io.papermc.paper.registry.data.dialog.input.DialogInput;
import io.papermc.paper.registry.data.dialog.type.DialogType;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.plugin.java.JavaPlugin;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

/**
 * Pre-join GUI Gatekeeper for Purpur 26.3.
 * Enforces a shared Server Invite Code on first registration plus salted PBKDF2
 * per-player passwords using Paper's Configuration-Phase Dialog API.
 */
@SuppressWarnings("UnstableApiUsage")
public final class MYTownGatekeeperPlugin extends JavaPlugin implements Listener {

    private static final Key ACTION_SUBMIT = Key.key("mytowngatekeeper:auth/submit");
    private static final Key ACTION_ABORT = Key.key("mytowngatekeeper:auth/abort");
    private static final Pattern VALID_USERNAME = Pattern.compile("^[a-zA-Z0-9_]{3,16}$");
    private static final int PBKDF2_ITERATIONS = 65_536;
    private static final int PBKDF2_KEY_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final int MAX_CONCURRENT_AUTH = 16;
    private static final int MAX_LOCKOUT_ENTRIES = 4096;

    private final SecureRandom secureRandom = new SecureRandom();
    private final Object stateLock = new Object();
    private final Semaphore pbkdf2Semaphore = new Semaphore(2);

    private final ConcurrentHashMap<PlayerCommonConnection, CompletableFuture<DialogSubmission>> pendingAuth =
        new ConcurrentHashMap<>();
    private final Set<String> activeConfiguringUsers = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, AccountRecord> accounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LockoutState> ipLockouts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LockoutState> userLockouts = new ConcurrentHashMap<>();

    private volatile String inviteCode;
    private volatile long sessionTtlSeconds;
    private volatile int authTimeoutSeconds;
    private volatile int minPasswordLength;
    private volatile int maxPasswordLength;
    private volatile int maxFailedAttempts;
    private volatile long lockoutSeconds;

    private File accountsFile;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        loadConfigurationSettings();
        this.accountsFile = new File(getDataFolder(), "accounts.yml");
        loadAccounts();

        Bukkit.getPluginManager().registerEvents(this, this);
        registerCommands();

        getLogger().info("MYTownGatekeeper enabled (" + accounts.size() + " registered accounts).");
    }

    @Override
    public void onDisable() {
        for (Map.Entry<PlayerCommonConnection, CompletableFuture<DialogSubmission>> entry : pendingAuth.entrySet()) {
            entry.getValue().complete(DialogSubmission.abortedResult());
        }
        pendingAuth.clear();
        saveAccounts();
    }

    private void loadConfigurationSettings() {
        synchronized (stateLock) {
            reloadConfig();
            this.inviteCode = getConfig().getString("invite-code", "CHANGE-ME").trim();
            long ttlHours = Math.max(0L, getConfig().getLong("session-ttl-hours", 24L));
            this.sessionTtlSeconds = ttlHours * 3600L;
            this.authTimeoutSeconds = Math.max(15, getConfig().getInt("auth-timeout-seconds", 90));
            this.minPasswordLength = Math.max(4, getConfig().getInt("min-password-length", 6));
            this.maxPasswordLength = Math.max(this.minPasswordLength, getConfig().getInt("max-password-length", 128));
            this.maxFailedAttempts = Math.max(1, getConfig().getInt("max-failed-attempts", 5));
            long lockMins = Math.max(1L, getConfig().getLong("lockout-minutes", 15L));
            this.lockoutSeconds = lockMins * 60L;

            if ("CHANGE-ME".equals(this.inviteCode) || this.inviteCode.isEmpty()) {
                getLogger().warning("invite-code is set to default placeholder! Rotate it immediately with /gatekeeper setinvite <code>.");
            }
        }
    }

    private void loadAccounts() {
        synchronized (stateLock) {
            accounts.clear();
            if (!accountsFile.exists()) {
                return;
            }
            YamlConfiguration yaml = YamlConfiguration.loadConfiguration(accountsFile);
            ConfigurationSection root = yaml.getConfigurationSection("accounts");
            if (root == null) {
                return;
            }
            for (String key : root.getKeys(false)) {
                ConfigurationSection sec = root.getConfigurationSection(key);
                if (sec == null) {
                    continue;
                }
                String displayName = sec.getString("username", key);
                String saltB64 = sec.getString("salt", "");
                String hashB64 = sec.getString("hash", "");
                String lastIp = sec.getString("last-ip", "");
                long lastLogin = sec.getLong("last-login-epoch", 0L);
                long createdAt = sec.getLong("created-at-epoch", 0L);
                if (!saltB64.isEmpty() && !hashB64.isEmpty()) {
                    accounts.put(key.toLowerCase(Locale.ROOT), new AccountRecord(
                        displayName, saltB64, hashB64, lastIp, lastLogin, createdAt
                    ));
                }
            }
        }
    }

    private void saveAccounts() {
        synchronized (stateLock) {
            if (!getDataFolder().exists() && !getDataFolder().mkdirs()) {
                getLogger().warning("Failed to create plugin data folder.");
                return;
            }
            YamlConfiguration yaml = new YamlConfiguration();
            for (Map.Entry<String, AccountRecord> entry : accounts.entrySet()) {
                String path = "accounts." + entry.getKey();
                AccountRecord rec = entry.getValue();
                yaml.set(path + ".username", rec.displayName);
                yaml.set(path + ".salt", rec.saltBase64);
                yaml.set(path + ".hash", rec.hashBase64);
                yaml.set(path + ".last-ip", rec.lastIp);
                yaml.set(path + ".last-login-epoch", rec.lastLoginEpochSec);
                yaml.set(path + ".created-at-epoch", rec.createdAtEpochSec);
            }
            Path target = accountsFile.toPath();
            Path tmp = target.resolveSibling("accounts.yml.tmp");
            try {
                yaml.save(tmp.toFile());
                try {
                    Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException ex) {
                    Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (IOException ex) {
                getLogger().severe("Failed to persist accounts.yml: " + ex.getMessage());
            }
        }
    }

    private void registerCommands() {
        getLifecycleManager().registerEventHandler(LifecycleEvents.COMMANDS, event ->
            event.registrar().register(
                "gatekeeper",
                "Manage MY-Town Gatekeeper authentication and invite codes",
                new GatekeeperCommand()
            )
        );
    }

    /**
     * Early handshake lockout, capacity, and anti-spoofing check before Purpur can
     * kick an already-online player during login setup.
     */
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onValidateLogin(PlayerConnectionValidateLoginEvent event) {
        if (!event.isAllowed()) {
            return;
        }
        String ip = extractIp(event.getConnection());
        long remainingSec = getLockoutRemainingSeconds(ipLockouts, ip);
        if (remainingSec > 0) {
            event.kickMessage(Component.text(
                "Too many failed authentication attempts from your IP. Try again in "
                    + formatDuration(remainingSec) + ".",
                NamedTextColor.RED
            ));
            return;
        }

        if (pendingAuth.size() >= MAX_CONCURRENT_AUTH) {
            event.kickMessage(Component.text(
                "Server authentication queue is busy. Please retry in a few seconds.",
                NamedTextColor.YELLOW
            ));
            return;
        }

        if (event.getConnection() instanceof PlayerLoginConnection loginConn) {
            PlayerProfile profile = loginConn.getAuthenticatedProfile();
            if (profile == null) {
                profile = loginConn.getUnsafeProfile();
            }
            String rawName = profile != null ? profile.getName() : null;
            if (rawName == null || !VALID_USERNAME.matcher(rawName).matches()) {
                event.kickMessage(Component.text("Invalid Minecraft username.", NamedTextColor.RED));
                return;
            }
            String userKey = rawName.toLowerCase(Locale.ROOT);
            long userLockSec = getLockoutRemainingSeconds(userLockouts, userKey);
            if (userLockSec > 0) {
                event.kickMessage(Component.text(
                    "Authentication temporarily locked for this account. Try again in " + formatDuration(userLockSec) + ".",
                    NamedTextColor.RED
                ));
                return;
            }
            if (isPlayerCurrentlyOnline(rawName) || activeConfiguringUsers.contains(userKey)) {
                getLogger().warning("Rejected duplicate unauthenticated login for online/active user '" + rawName + "' from " + ip + ".");
                event.kickMessage(Component.text(
                    "That player is already logged in.",
                    NamedTextColor.RED
                ));
            }
        }
    }

    /**
     * Configuration-phase pre-world authentication gate.
     */
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPlayerConfigure(AsyncPlayerConnectionConfigureEvent event) {
        PlayerConfigurationConnection conn = event.getConnection();
        String rawUsername = conn.getProfile().getName();
        if (rawUsername == null || !VALID_USERNAME.matcher(rawUsername).matches()) {
            conn.disconnect(Component.text("Invalid Minecraft username.", NamedTextColor.RED));
            return;
        }

        String userKey = rawUsername.toLowerCase(Locale.ROOT);
        String ip = extractIp(conn);

        if (isPlayerCurrentlyOnline(rawUsername) || !activeConfiguringUsers.add(userKey)) {
            conn.disconnect(Component.text("That player is already logged in or authenticating.", NamedTextColor.RED));
            return;
        }

        try {
            long lockSec = Math.max(
                getLockoutRemainingSeconds(ipLockouts, ip),
                getLockoutRemainingSeconds(userLockouts, userKey)
            );
            if (lockSec > 0) {
                conn.disconnect(Component.text(
                    "Authentication temporarily locked. Try again in " + formatDuration(lockSec) + ".",
                    NamedTextColor.RED
                ));
                return;
            }

            AccountRecord existing = accounts.get(userKey);
            long now = Instant.now().getEpochSecond();

            if (existing != null && sessionTtlSeconds > 0
                && !ip.isEmpty() && ip.equals(existing.lastIp)
                && (now - existing.lastLoginEpochSec) <= sessionTtlSeconds
                && !isPlayerCurrentlyOnline(rawUsername)) {
                AccountRecord updated = existing.withLogin(ip, now);
                accounts.put(userKey, updated);
                saveAccounts();
                getLogger().info("Resumed IP session for " + rawUsername + " (" + ip + ").");
                return;
            }

            String errorBanner = null;
            while (conn.isConnected()) {
                long currentLock = Math.max(
                    getLockoutRemainingSeconds(ipLockouts, ip),
                    getLockoutRemainingSeconds(userLockouts, userKey)
                );
                if (currentLock > 0) {
                    conn.disconnect(Component.text(
                        "Too many failed attempts. Locked for " + formatDuration(currentLock) + ".",
                        NamedTextColor.RED
                    ));
                    return;
                }

                if (pendingAuth.size() >= MAX_CONCURRENT_AUTH) {
                    conn.disconnect(Component.text(
                        "Server authentication queue is busy. Please retry in a few seconds.",
                        NamedTextColor.YELLOW
                    ));
                    return;
                }

                existing = accounts.get(userKey);
                boolean isRegistration = (existing == null);

                Dialog dialog = isRegistration
                    ? buildRegistrationDialog(rawUsername, errorBanner)
                    : buildLoginDialog(rawUsername, errorBanner, remainingAttempts(ip, userKey));

                CompletableFuture<DialogSubmission> future = new CompletableFuture<>();
                pendingAuth.put(conn, future);
                DialogSubmission submission;
                try {
                    conn.getAudience().showDialog(dialog);
                    submission = awaitSubmission(conn, future);
                } finally {
                    pendingAuth.remove(conn, future);
                }

                if (submission == null) {
                    if (conn.isConnected()) {
                        conn.disconnect(Component.text("Authentication timed out. Please reconnect.", NamedTextColor.RED));
                    }
                    return;
                }
                if (submission.aborted) {
                    if (conn.isConnected()) {
                        conn.disconnect(Component.text("Authentication cancelled.", NamedTextColor.YELLOW));
                    }
                    return;
                }

                if (isRegistration) {
                    String enteredInvite = submission.inviteCode == null ? "" : submission.inviteCode.trim();
                    String pwd = submission.password == null ? "" : submission.password;
                    String pwdConfirm = submission.passwordConfirm == null ? "" : submission.passwordConfirm;

                    if (!constantTimeEquals(enteredInvite, this.inviteCode)) {
                        int left = recordFailure(ip, userKey);
                        getLogger().warning("Failed invite attempt for " + rawUsername + " from " + ip + " (" + left + " left)");
                        if (left <= 0) {
                            conn.disconnect(Component.text("Too many failed invite attempts. Try again later.", NamedTextColor.RED));
                            return;
                        }
                        errorBanner = "Invalid Server Invite Code (" + left + " attempts remaining).";
                        continue;
                    }

                    if (pwd.length() < minPasswordLength || pwd.length() > maxPasswordLength) {
                        errorBanner = "Personal password must be " + minPasswordLength + "-" + maxPasswordLength + " characters.";
                        continue;
                    }
                    if (!pwd.equals(pwdConfirm)) {
                        errorBanner = "Passwords do not match. Please re-enter them.";
                        continue;
                    }

                    AccountRecord created;
                    try {
                        created = createAccountRecord(rawUsername, pwd, ip);
                    } catch (IllegalStateException busyEx) {
                        conn.disconnect(Component.text("Authentication service busy. Please retry.", NamedTextColor.YELLOW));
                        return;
                    }
                    AccountRecord race = accounts.putIfAbsent(userKey, created);
                    if (race != null) {
                        errorBanner = "Account already exists. Please log in with your password.";
                        continue;
                    }
                    clearFailures(ip, userKey);
                    saveAccounts();
                    getLogger().info("Registered new account " + rawUsername + " from " + ip + ".");
                    return;
                } else {
                    String pwd = submission.password == null ? "" : submission.password;
                    boolean validPwd;
                    try {
                        validPwd = verifyPassword(pwd, existing);
                    } catch (IllegalStateException busyEx) {
                        conn.disconnect(Component.text("Authentication service busy. Please retry.", NamedTextColor.YELLOW));
                        return;
                    }
                    if (validPwd) {
                        accounts.put(userKey, existing.withLogin(ip, Instant.now().getEpochSecond()));
                        clearFailures(ip, userKey);
                        saveAccounts();
                        getLogger().info("Authenticated " + rawUsername + " from " + ip + ".");
                        return;
                    }
                    int left = recordFailure(ip, userKey);
                    getLogger().warning("Failed password login for " + rawUsername + " from " + ip + " (" + left + " left)");
                    if (left <= 0) {
                        conn.disconnect(Component.text("Too many failed password attempts. Try again later.", NamedTextColor.RED));
                        return;
                    }
                    errorBanner = "Incorrect personal password (" + left + " attempts remaining).";
                }
            }
        } finally {
            activeConfiguringUsers.remove(userKey);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onCustomClick(PlayerCustomClickEvent event) {
        Key id = event.getIdentifier();
        if (!"mytowngatekeeper".equals(id.namespace())) {
            return;
        }
        CompletableFuture<DialogSubmission> future = pendingAuth.get(event.getCommonConnection());
        if (future == null) {
            return;
        }
        if (ACTION_ABORT.equals(id)) {
            future.complete(DialogSubmission.abortedResult());
            return;
        }
        if (ACTION_SUBMIT.equals(id)) {
            DialogResponseView view = event.getDialogResponseView();
            if (view == null) {
                future.complete(DialogSubmission.abortedResult());
                return;
            }
            String invite = view.getText("invite_code");
            String pass = view.getText("password");
            String passConfirm = view.getText("password_confirm");
            future.complete(new DialogSubmission(false, invite, pass, passConfirm));
        }
    }

    private DialogSubmission awaitSubmission(PlayerConfigurationConnection conn, CompletableFuture<DialogSubmission> future) {
        long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(authTimeoutSeconds);
        while (conn.isConnected()) {
            long remainingMs = TimeUnit.NANOSECONDS.toMillis(deadlineNanos - System.nanoTime());
            if (remainingMs <= 0) {
                return null;
            }
            long stepMs = Math.min(remainingMs, 1500L);
            try {
                return future.get(stepMs, TimeUnit.MILLISECONDS);
            } catch (TimeoutException ignored) {
                // Keep polling connection health until authTimeoutSeconds expires.
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return null;
            } catch (ExecutionException ex) {
                return null;
            }
        }
        return null;
    }

    private Dialog buildRegistrationDialog(String username, String errorBanner) {
        List<DialogBody> body = new ArrayList<>();
        body.add(DialogBody.plainMessage(
            Component.text("Welcome, " + username + "! Enter the Server Invite Code and create your personal password to claim this username.", NamedTextColor.GRAY),
            340
        ));
        if (errorBanner != null && !errorBanner.isEmpty()) {
            body.add(DialogBody.plainMessage(
                Component.text(errorBanner, NamedTextColor.RED, TextDecoration.BOLD),
                340
            ));
        }
        return Dialog.create(factory -> factory.empty()
            .base(DialogBase.builder(Component.text("MY-Town Registration", NamedTextColor.GOLD, TextDecoration.BOLD))
                .canCloseWithEscape(false)
                .body(body)
                .inputs(List.of(
                    DialogInput.text("invite_code", Component.text("Server Invite Code", NamedTextColor.AQUA))
                        .width(260)
                        .maxLength(128)
                        .build(),
                    DialogInput.text("password", Component.text("Create Personal Password (min " + minPasswordLength + " chars)", NamedTextColor.GREEN))
                        .width(260)
                        .maxLength(maxPasswordLength)
                        .build(),
                    DialogInput.text("password_confirm", Component.text("Confirm Personal Password", NamedTextColor.GREEN))
                        .width(260)
                        .maxLength(maxPasswordLength)
                        .build()
                ))
                .build()
            )
            .type(DialogType.confirmation(
                ActionButton.builder(Component.text("Register & Join", NamedTextColor.GREEN, TextDecoration.BOLD))
                    .tooltip(Component.text("Verify invite code and create your server account", NamedTextColor.GRAY))
                    .action(DialogAction.customClick(ACTION_SUBMIT, null))
                    .build(),
                ActionButton.builder(Component.text("Disconnect", NamedTextColor.RED))
                    .tooltip(Component.text("Leave the server", NamedTextColor.GRAY))
                    .action(DialogAction.customClick(ACTION_ABORT, null))
                    .build()
            ))
        );
    }

    private Dialog buildLoginDialog(String username, String errorBanner, int attemptsLeft) {
        List<DialogBody> body = new ArrayList<>();
        body.add(DialogBody.plainMessage(
            Component.text("Welcome back, " + username + ". Enter your personal account password to continue.", NamedTextColor.GRAY),
            340
        ));
        if (errorBanner != null && !errorBanner.isEmpty()) {
            body.add(DialogBody.plainMessage(
                Component.text(errorBanner, NamedTextColor.RED, TextDecoration.BOLD),
                340
            ));
        }
        return Dialog.create(factory -> factory.empty()
            .base(DialogBase.builder(Component.text("MY-Town Login", NamedTextColor.AQUA, TextDecoration.BOLD))
                .canCloseWithEscape(false)
                .body(body)
                .inputs(List.of(
                    DialogInput.text("password", Component.text("Personal Password", NamedTextColor.GREEN))
                        .width(260)
                        .maxLength(maxPasswordLength)
                        .build()
                ))
                .build()
            )
            .type(DialogType.confirmation(
                ActionButton.builder(Component.text("Login", NamedTextColor.GREEN, TextDecoration.BOLD))
                    .tooltip(Component.text(attemptsLeft + " attempts remaining", NamedTextColor.GRAY))
                    .action(DialogAction.customClick(ACTION_SUBMIT, null))
                    .build(),
                ActionButton.builder(Component.text("Disconnect", NamedTextColor.RED))
                    .tooltip(Component.text("Leave the server", NamedTextColor.GRAY))
                    .action(DialogAction.customClick(ACTION_ABORT, null))
                    .build()
            ))
        );
    }

    private AccountRecord createAccountRecord(String username, String password, String ip) {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        byte[] hash = pbkdf2(password, salt);
        long now = Instant.now().getEpochSecond();
        return new AccountRecord(
            username,
            Base64.getEncoder().encodeToString(salt),
            Base64.getEncoder().encodeToString(hash),
            ip,
            now,
            now
        );
    }

    private boolean verifyPassword(String password, AccountRecord record) {
        byte[] salt = Base64.getDecoder().decode(record.saltBase64);
        byte[] expectedHash = Base64.getDecoder().decode(record.hashBase64);
        byte[] actualHash = pbkdf2(password, salt);
        return MessageDigest.isEqual(expectedHash, actualHash);
    }

    private byte[] pbkdf2(String password, byte[] salt) {
        try {
            if (!pbkdf2Semaphore.tryAcquire(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("PBKDF2 concurrency limit reached");
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("PBKDF2 interrupted", ex);
        }
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 unavailable", ex);
        } finally {
            pbkdf2Semaphore.release();
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String extractIp(PlayerConnection conn) {
        InetSocketAddress addr = conn.getClientAddress();
        if (addr == null) {
            return "";
        }
        InetAddress inet = addr.getAddress();
        return inet != null ? inet.getHostAddress() : addr.getHostString();
    }

    private static boolean isPlayerCurrentlyOnline(String username) {
        for (Player p : Bukkit.getOnlinePlayers()) {
            if (p.getName().equalsIgnoreCase(username)) {
                return true;
            }
        }
        return false;
    }

    private int remainingAttempts(String ip, String userKey) {
        int ipFails = getFailureCount(ipLockouts, ip);
        int userFails = getFailureCount(userLockouts, userKey);
        return Math.max(0, maxFailedAttempts - Math.max(ipFails, userFails));
    }

    private int recordFailure(String ip, String userKey) {
        int ipLeft = incrementFailure(ipLockouts, ip);
        int userLeft = incrementFailure(userLockouts, userKey);
        return Math.min(ipLeft, userLeft);
    }

    private int incrementFailure(ConcurrentHashMap<String, LockoutState> map, String key) {
        if (key == null || key.isEmpty()) {
            return maxFailedAttempts;
        }
        long now = Instant.now().getEpochSecond();
        if (map.size() >= 256) {
            pruneExpiredLockouts(map, now);
        }
        if (!map.containsKey(key) && map.size() >= MAX_LOCKOUT_ENTRIES) {
            return 0;
        }
        LockoutState updated = map.compute(key, (k, cur) -> {
            if (cur == null || (cur.lockedUntilEpochSec > 0 && cur.lockedUntilEpochSec <= now)) {
                int fails = 1;
                long lockUntil = fails >= maxFailedAttempts ? now + lockoutSeconds : 0L;
                return new LockoutState(fails, lockUntil);
            }
            int fails = cur.failures + 1;
            long lockUntil = fails >= maxFailedAttempts ? now + lockoutSeconds : cur.lockedUntilEpochSec;
            return new LockoutState(fails, lockUntil);
        });
        return Math.max(0, maxFailedAttempts - updated.failures);
    }

    private static void pruneExpiredLockouts(ConcurrentHashMap<String, LockoutState> map, long now) {
        map.entrySet().removeIf(e -> e.getValue().lockedUntilEpochSec > 0 && e.getValue().lockedUntilEpochSec <= now);
    }

    private int getFailureCount(ConcurrentHashMap<String, LockoutState> map, String key) {
        if (key == null || key.isEmpty()) {
            return 0;
        }
        LockoutState state = map.get(key);
        if (state == null) {
            return 0;
        }
        long now = Instant.now().getEpochSecond();
        if (state.lockedUntilEpochSec > 0 && state.lockedUntilEpochSec <= now) {
            map.remove(key, state);
            return 0;
        }
        return state.failures;
    }

    private long getLockoutRemainingSeconds(ConcurrentHashMap<String, LockoutState> map, String key) {
        if (key == null || key.isEmpty()) {
            return 0L;
        }
        LockoutState state = map.get(key);
        if (state == null || state.lockedUntilEpochSec <= 0) {
            return 0L;
        }
        long now = Instant.now().getEpochSecond();
        long rem = state.lockedUntilEpochSec - now;
        if (rem <= 0) {
            map.remove(key, state);
            return 0L;
        }
        return rem;
    }

    private void clearFailures(String ip, String userKey) {
        if (ip != null && !ip.isEmpty()) {
            ipLockouts.remove(ip);
        }
        if (userKey != null && !userKey.isEmpty()) {
            userLockouts.remove(userKey);
        }
    }

    private static String formatDuration(long seconds) {
        long mins = seconds / 60;
        long secs = seconds % 60;
        return mins > 0 ? (mins + "m " + secs + "s") : (secs + "s");
    }

    private record DialogSubmission(boolean aborted, String inviteCode, String password, String passwordConfirm) {
        static DialogSubmission abortedResult() {
            return new DialogSubmission(true, null, null, null);
        }
    }

    private record AccountRecord(
        String displayName,
        String saltBase64,
        String hashBase64,
        String lastIp,
        long lastLoginEpochSec,
        long createdAtEpochSec
    ) {
        AccountRecord withLogin(String ip, long nowEpochSec) {
            return new AccountRecord(displayName, saltBase64, hashBase64, ip, nowEpochSec, createdAtEpochSec);
        }
    }

    private record LockoutState(int failures, long lockedUntilEpochSec) {
    }

    private final class GatekeeperCommand implements BasicCommand {
        @Override
        public boolean canUse(CommandSender sender) {
            return sender instanceof ConsoleCommandSender
                || sender.isOp()
                || sender.hasPermission("mytown.gatekeeper.admin");
        }

        @Override
        public String permission() {
            return "mytown.gatekeeper.admin";
        }

        @Override
        public void execute(CommandSourceStack stack, String[] args) {
            CommandSender sender = stack.getSender();
            if (!canUse(sender)) {
                sender.sendMessage(Component.text("You do not have permission.", NamedTextColor.RED));
                return;
            }
            if (args.length == 0 || "help".equalsIgnoreCase(args[0])) {
                sender.sendMessage(Component.text(
                    "Gatekeeper commands: /gatekeeper status | setinvite <code> | resetpassword <user> | clearlockout <ip|user|all> | reload",
                    NamedTextColor.AQUA
                ));
                return;
            }

            switch (args[0].toLowerCase(Locale.ROOT)) {
                case "status" -> {
                    long activeLocks = ipLockouts.values().stream().filter(s -> s.lockedUntilEpochSec > Instant.now().getEpochSecond()).count()
                        + userLockouts.values().stream().filter(s -> s.lockedUntilEpochSec > Instant.now().getEpochSecond()).count();
                    sender.sendMessage(Component.text(
                        "MYTownGatekeeper Status: registered=" + accounts.size()
                            + ", activeLockouts=" + activeLocks
                            + ", sessionTTLHours=" + (sessionTtlSeconds / 3600L)
                            + ", inviteCode=" + inviteCode,
                        NamedTextColor.GREEN
                    ));
                }
                case "setinvite" -> {
                    if (args.length < 2) {
                        sender.sendMessage(Component.text("Usage: /gatekeeper setinvite <new_code>", NamedTextColor.RED));
                        return;
                    }
                    String newCode = args[1].trim();
                    if (newCode.length() < 4) {
                        sender.sendMessage(Component.text("Invite code must be at least 4 characters.", NamedTextColor.RED));
                        return;
                    }
                    synchronized (stateLock) {
                        inviteCode = newCode;
                        getConfig().set("invite-code", newCode);
                        saveConfig();
                    }
                    sender.sendMessage(Component.text("Updated server invite code.", NamedTextColor.GREEN));
                }
                case "resetpassword" -> {
                    if (args.length < 2) {
                        sender.sendMessage(Component.text("Usage: /gatekeeper resetpassword <username>", NamedTextColor.RED));
                        return;
                    }
                    String targetKey = args[1].toLowerCase(Locale.ROOT);
                    AccountRecord removed = accounts.remove(targetKey);
                    if (removed == null) {
                        sender.sendMessage(Component.text("No registered account found for '" + args[1] + "'.", NamedTextColor.YELLOW));
                        return;
                    }
                    userLockouts.remove(targetKey);
                    saveAccounts();
                    Player online = Bukkit.getPlayerExact(removed.displayName);
                    if (online != null && online.isOnline()) {
                        online.kick(Component.text("Your server password was reset by an admin. Rejoin with the invite code to set a new password.", NamedTextColor.YELLOW));
                    }
                    sender.sendMessage(Component.text("Reset account for " + removed.displayName + ". They must re-register with the invite code.", NamedTextColor.GREEN));
                }
                case "clearlockout" -> {
                    if (args.length < 2) {
                        sender.sendMessage(Component.text("Usage: /gatekeeper clearlockout <ip|username|all>", NamedTextColor.RED));
                        return;
                    }
                    if ("all".equalsIgnoreCase(args[1])) {
                        ipLockouts.clear();
                        userLockouts.clear();
                        sender.sendMessage(Component.text("Cleared all IP and username lockouts.", NamedTextColor.GREEN));
                    } else {
                        ipLockouts.remove(args[1]);
                        userLockouts.remove(args[1].toLowerCase(Locale.ROOT));
                        sender.sendMessage(Component.text("Cleared lockout for " + args[1] + ".", NamedTextColor.GREEN));
                    }
                }
                case "reload" -> {
                    loadConfigurationSettings();
                    sender.sendMessage(Component.text("Reloaded MYTownGatekeeper configuration.", NamedTextColor.GREEN));
                }
                default -> sender.sendMessage(Component.text("Unknown subcommand. Use /gatekeeper status", NamedTextColor.RED));
            }
        }

        @Override
        public Collection<String> suggest(CommandSourceStack stack, String[] args) {
            if (!canUse(stack.getSender())) {
                return List.of();
            }
            if (args.length <= 1) {
                return List.of("status", "setinvite", "resetpassword", "clearlockout", "reload");
            }
            if (args.length == 2 && "resetpassword".equalsIgnoreCase(args[0])) {
                return accounts.values().stream().map(AccountRecord::displayName).toList();
            }
            return List.of();
        }
    }
}
