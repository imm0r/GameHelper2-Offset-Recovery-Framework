// Ghidra script: recover update-prone static offsets from semantic recipes.
// @author Arsenic

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class OffsetRecoveryFramework extends GhidraScript {
    private static final boolean VERBOSE = false;
    private static final int HIGH_CONFIDENCE = 85;
    private static final int MAX_GAME_STATES_PROVIDER_SCAN_BYTES = 0x180;
    private static final int MAX_FILE_ROOT_FINDER_SCAN_BYTES = 0x180;
    private static final int MAX_AREA_COUNTER_SCAN_BYTES = 0x300;

    private final List<StringHit> stringCache = new ArrayList<>();
    private final RecoverySummary summary = new RecoverySummary();

    @Override
    public void run() throws Exception {
        println("GameHelper2 Offset Recovery Framework");
        println("Program: " + currentProgram.getName());
        println("");

        cacheDefinedStrings();

        for (OffsetRecipe recipe : Arrays.asList(
            new GameStatesRecipe(),
            new FileRootRecipe(),
            new AreaChangeCounterRecipe()
        )) {
            runRecipe(recipe);
            println("");
        }

        summary.print();
    }

    private void runRecipe(OffsetRecipe recipe) {
        println("== " + recipe.name() + " ==");
        try {
            List<RecoveryResult> candidates = recipe.recoverCandidates();
            sortCandidates(candidates);

            if (candidates.isEmpty()) {
                println("FAILED: " + recipe.failureReason());
                summary.addFailure(recipe.name(), recipe.failureReason());
                return;
            }

            RecoveryResult best = candidates.get(0);
            printResult(best);
            annotate(best);
            summary.addSuccess(best, candidates.size());
        }
        catch (Exception e) {
            String reason = e.getClass().getSimpleName() + ": " + e.getMessage();
            println("FAILED: " + reason);
            summary.addFailure(recipe.name(), reason);
        }
    }

    private void sortCandidates(List<RecoveryResult> candidates) {
        Collections.sort(candidates, new Comparator<RecoveryResult>() {
            @Override
            public int compare(RecoveryResult left, RecoveryResult right) {
                return Integer.compare(right.score, left.score);
            }
        });
    }

    private void printResult(RecoveryResult result) {
        println("Anchor string       : " + result.anchor.address + "  \"" + result.anchor.value + "\"");
        println("String reference    : " + result.stringReferenceAddress);
        println("XREF function       : " + formatFunction(result.xrefFunction));
        println("Source function     : " + formatFunction(result.sourceFunction));
        if (result.callDepth >= 0) {
            println("Call depth          : " + result.callDepth);
        }
        println("Pattern start       : " + result.match.patternAddress);
        println("Target instruction  : " + result.match.instructionAddress + "  " + result.match.instructionKind);
        println("Resolved address    : " + result.match.resolvedAddress);
        println("Pattern             : " + result.match.pattern);
        println("BytesToSkip         : " + result.match.bytesToSkip);
        println("Expected            : " + result.expectedStatus);
        println("Confidence          : " + confidenceLabel(result.score) + " (" + result.score + "/100)");

        if (VERBOSE) {
            printList("Score reasons", result.scoreReasons);
            printList("Validations", result.validations);
        }
    }

    private void printList(String title, List<String> values) {
        if (values.isEmpty()) {
            return;
        }
        println(title + "       :");
        for (String value : values) {
            println("  - " + value);
        }
    }

    private String formatFunction(Function function) {
        if (function == null) {
            return "<none>";
        }
        return function.getName() + " @ " + function.getEntryPoint();
    }

    private void annotate(RecoveryResult result) {
        String comment = "Recovered " + result.offsetName + " candidate: "
            + result.match.resolvedAddress + " via " + result.match.instructionKind + ".";

        setEOLComment(result.match.instructionAddress, comment);
        createBookmark(result.anchor.address, BookmarkType.ANALYSIS,
            "GameHelper2 Offset: " + result.offsetName + " anchor string.");
        createBookmark(result.stringReferenceAddress, BookmarkType.ANALYSIS,
            "GameHelper2 Offset: " + result.offsetName + " anchor XREF.");
        createBookmark(result.match.instructionAddress, BookmarkType.ANALYSIS, "GameHelper2 Offset: " + comment);
        createBookmark(result.match.resolvedAddress, BookmarkType.ANALYSIS,
            "GameHelper2 Offset: " + result.offsetName + " static candidate.");

        if (result.score >= HIGH_CONFIDENCE) {
            createLabelIfMissing(result.match.resolvedAddress, result.staticLabel);
            if (result.sourceFunction != null && result.sourceLabel != null) {
                createLabelIfMissing(result.sourceFunction.getEntryPoint(), result.sourceLabel);
            }
        }
    }

    private void createLabelIfMissing(Address address, String label) {
        if (address == null || label == null || label.length() == 0) {
            return;
        }

        try {
            createLabel(address, label, false, SourceType.USER_DEFINED);
        }
        catch (Exception e) {
            println("WARN: could not create label " + label + " at " + address + ": " + e.getMessage());
        }
    }

    private void cacheDefinedStrings() {
        stringCache.clear();
        DataIterator iterator = currentProgram.getListing().getDefinedData(true);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Data data = iterator.next();
            Object value = data.getValue();
            if (value instanceof String) {
                stringCache.add(new StringHit((String)value, data.getAddress()));
            }
        }
        println("Cached defined strings: " + stringCache.size());
        println("");
    }

    private List<StringHit> findAnchors(AnchorSpec... anchors) {
        List<StringHit> hits = new ArrayList<>();
        Set<Address> seen = new HashSet<>();
        for (AnchorSpec anchor : anchors) {
            for (StringHit hit : stringCache) {
                if (seen.contains(hit.address)) {
                    continue;
                }
                if (anchor.matches(hit.value)) {
                    hits.add(hit);
                    seen.add(hit.address);
                }
            }
        }
        return hits;
    }

    private List<Reference> referencesTo(Address address) {
        return Arrays.asList(getReferencesTo(address));
    }

    private List<Function> directCalls(Function function) {
        return directCallsBefore(function, null);
    }

    private List<Function> directCallsBefore(Function function, Address beforeAddress) {
        List<Function> calls = new ArrayList<>();
        if (!hasInstructionBody(function)) {
            return calls;
        }

        Set<Address> seenEntries = new HashSet<>();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (beforeAddress != null && instruction.getAddress().compareTo(beforeAddress) >= 0) {
                break;
            }
            if (!"CALL".equals(instruction.getMnemonicString())) {
                continue;
            }

            for (Reference reference : getReferencesFrom(instruction.getAddress())) {
                RefType type = reference.getReferenceType();
                if (!type.isCall()) {
                    continue;
                }

                Function called = getFunctionAt(reference.getToAddress());
                if (hasInstructionBody(called) && seenEntries.add(called.getEntryPoint())) {
                    calls.add(called);
                }
            }
        }
        return calls;
    }

    private List<Function> directCallsToDepth(Function root, int maxDepth) {
        List<Function> result = new ArrayList<>();
        if (!hasInstructionBody(root)) {
            return result;
        }

        Set<Address> seenEntries = new HashSet<>();
        List<FunctionDepth> frontier = new ArrayList<>();
        frontier.add(new FunctionDepth(root, 0));

        for (int i = 0; i < frontier.size(); i++) {
            FunctionDepth current = frontier.get(i);
            if (current.depth >= maxDepth) {
                continue;
            }

            for (Function called : directCalls(current.function)) {
                if (seenEntries.add(called.getEntryPoint())) {
                    result.add(called);
                    frontier.add(new FunctionDepth(called, current.depth + 1));
                }
            }
        }
        return result;
    }

    private int callDepth(Function root, Function target, int maxDepth) {
        if (!hasInstructionBody(root) || target == null) {
            return -1;
        }

        if (root.getEntryPoint().equals(target.getEntryPoint())) {
            return 0;
        }

        Set<Address> seenEntries = new HashSet<>();
        List<FunctionDepth> frontier = new ArrayList<>();
        frontier.add(new FunctionDepth(root, 0));

        for (int i = 0; i < frontier.size(); i++) {
            FunctionDepth current = frontier.get(i);
            if (current.depth >= maxDepth) {
                continue;
            }

            for (Function called : directCalls(current.function)) {
                if (called.getEntryPoint().equals(target.getEntryPoint())) {
                    return current.depth + 1;
                }
                if (seenEntries.add(called.getEntryPoint())) {
                    frontier.add(new FunctionDepth(called, current.depth + 1));
                }
            }
        }
        return -1;
    }

    private List<Instruction> instructionsInWindow(Function function, Address start, int maxBytes) {
        List<Instruction> result = new ArrayList<>();
        if (!hasInstructionBody(function) || start == null) {
            return result;
        }

        Address functionEnd = function.getBody().getMaxAddress();
        if (functionEnd == null) {
            return result;
        }

        Address end;
        try {
            end = start.addNoWrap(maxBytes);
        }
        catch (Exception e) {
            end = functionEnd;
        }
        if (end.compareTo(functionEnd) > 0) {
            end = functionEnd;
        }

        Instruction instruction = getInstructionAt(start);
        if (instruction == null) {
            instruction = getInstructionAfter(start);
        }

        while (instruction != null
            && instruction.getAddress().compareTo(end) <= 0
            && function.getBody().contains(instruction.getAddress())) {
            result.add(instruction);
            instruction = getInstructionAfter(instruction);
        }
        return result;
    }

    private boolean hasInstructionBody(Function function) {
        return function != null
            && !function.isExternal()
            && function.getEntryPoint() != null
            && function.getBody() != null
            && !function.getBody().isEmpty();
    }

    private PatternMatch findStaticQwordNullCheck(Function function) throws Exception {
        for (Instruction instruction : instructionsInWindow(
            function,
            function.getEntryPoint(),
            MAX_GAME_STATES_PROVIDER_SCAN_BYTES
        )) {
            Address address = instruction.getAddress();
            if (bytesAt(address, 0x48, 0x39, 0x2d)) {
                Address resolved = resolveRipRelative(address, 7, 3);
                boolean hasPrologueContext = bytesAt(address.subtract(5), 0x48, 0x8b, 0xf1, 0x33, 0xed);
                return new PatternMatch(
                    hasPrologueContext ? address.subtract(5) : address,
                    address,
                    resolved,
                    hasPrologueContext
                        ? "48 8B F1 33 ED 48 39 2D ^ ?? ?? ?? ?? 0F 85 ?? ?? ?? ??"
                        : "48 39 2D ^ ?? ?? ?? ?? 0F 85 ?? ?? ?? ??",
                    hasPrologueContext ? 8 : 3,
                    "static qword null-check"
                );
            }

            if (bytesAt(address, 0x48, 0x83, 0x3d) && u8(address.add(7)) == 0x00) {
                return new PatternMatch(
                    address,
                    address,
                    resolveRipRelative(address, 8, 3),
                    "48 83 3D ^ ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ??",
                    3,
                    "static qword null-check"
                );
            }
        }
        return null;
    }

    private PatternMatch findStaticQwordReturn(Function function) throws Exception {
        for (Instruction instruction : instructionsInWindow(
            function,
            function.getEntryPoint(),
            MAX_FILE_ROOT_FINDER_SCAN_BYTES
        )) {
            Address address = instruction.getAddress();
            if (!bytesAt(address, 0x48, 0x8b, 0x05) || !hasNearbyRet(address, 0x18)) {
                continue;
            }

            boolean hasTlsInitContext = bytesAt(function.getEntryPoint(), 0x48, 0x83, 0xec, 0x28, 0x65, 0x48)
                && address.subtract(function.getEntryPoint()) < 0x80;
            return new PatternMatch(
                hasTlsInitContext ? function.getEntryPoint() : address,
                address,
                resolveRipRelative(address, 7, 3),
                hasTlsInitContext
                    ? "48 83 EC 28 65 48 8B 04 25 58 00 00 00 B9 10 00 00 00 48 8B 00 8B 0C 01 39 0D ?? ?? ?? ?? 7E ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ^ ?? ?? ?? ?? 48 83 C4 28 C3"
                    : "48 8B 05 ^ ?? ?? ?? ?? 48 83 C4 ?? C3",
                hasTlsInitContext ? (int)address.subtract(function.getEntryPoint()) + 3 : 3,
                "static qword return"
            );
        }
        return null;
    }

    private PatternMatch findDwordIncrementAfter(Function function, Address anchorReference) throws Exception {
        for (Instruction instruction : instructionsInWindow(function, anchorReference, MAX_AREA_COUNTER_SCAN_BYTES)) {
            Address address = instruction.getAddress();
            if (!bytesAt(address, 0xff, 0x05)) {
                continue;
            }

            boolean hasTlsContext = hasAreaChangeTlsContext(address);
            return new PatternMatch(
                hasTlsContext ? address.subtract(0x4e) : address,
                address,
                resolveRipRelative(address, 6, 2),
                hasTlsContext
                    ? "65 48 8B 04 25 58 00 00 00 B9 10 00 00 00 48 8B 00 8B 0C 01 39 0D ?? ?? ?? ?? 7E ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 05 ^ ?? ?? ?? ?? 4C 8B 06 49 8D 50 20"
                    : "FF 05 ^ ?? ?? ?? ??",
                hasTlsContext ? 0x50 : 2,
                "static dword increment"
            );
        }
        return null;
    }

    private boolean hasNearbyRet(Address address, int maxBytes) {
        Instruction instruction = getInstructionAt(address);
        int scanned = 0;
        while (instruction != null && scanned <= maxBytes) {
            if ("RET".equals(instruction.getMnemonicString())) {
                return true;
            }
            instruction = getInstructionAfter(instruction);
            scanned += instruction == null ? maxBytes + 1 : instruction.getLength();
        }
        return false;
    }

    private boolean hasAreaChangeTlsContext(Address incrementAddress) {
        try {
            Address start = incrementAddress.subtract(0x4e);
            return bytesAt(start, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x58)
                && bytesAt(incrementAddress.add(6), 0x4c, 0x8b);
        }
        catch (Exception e) {
            return false;
        }
    }

    private Address resolveRipRelative(Address instructionAddress, int instructionLength, int displacementOffset)
            throws Exception {
        int displacement = u8(instructionAddress.add(displacementOffset))
            | (u8(instructionAddress.add(displacementOffset + 1)) << 8)
            | (u8(instructionAddress.add(displacementOffset + 2)) << 16)
            | (u8(instructionAddress.add(displacementOffset + 3)) << 24);

        long targetOffset = instructionAddress.getOffset() + instructionLength + displacement;
        return instructionAddress.getAddressSpace().getAddress(targetOffset);
    }

    private boolean bytesAt(Address address, int... expected) {
        try {
            for (int i = 0; i < expected.length; i++) {
                if (u8(address.add(i)) != expected[i]) {
                    return false;
                }
            }
            return true;
        }
        catch (Exception e) {
            return false;
        }
    }

    private int u8(Address address) throws MemoryAccessException {
        return getByte(address) & 0xff;
    }

    private Address expectedAddress(String offsetText) {
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(offsetText, 16));
        }
        catch (Exception e) {
            return null;
        }
    }

    private int refsToScore(Address address, int score, List<String> reasons, List<String> validations) {
        int count = getReferencesTo(address).length;
        if (count >= 2) {
            reasons.add("resolved address has " + count + " XREFs");
            validations.add("resolved address is referenced elsewhere");
            return score;
        }
        validations.add("resolved address has low XREF count: " + count);
        return 0;
    }

    private int proximityScore(Address from, Address to, long maxDistance, int score, String label, List<String> reasons) {
        long distance = to.subtract(from);
        if (distance >= 0 && distance < maxDistance) {
            reasons.add(label + " within 0x" + Long.toHexString(maxDistance) + " bytes");
            return score;
        }
        return 0;
    }

    private RecoveryResult buildResult(String offsetName, String staticLabel, String sourceLabel,
            String expectedAddressText, StringHit anchor, Address stringReferenceAddress, Function xrefFunction,
            Function sourceFunction, int callDepth, PatternMatch match, int score, List<String> scoreReasons,
            List<String> validations) {
        Address expected = expectedAddress(expectedAddressText);
        String expectedStatus = "not configured";
        if (expected != null) {
            if (expected.equals(match.resolvedAddress)) {
                expectedStatus = "matches " + expected;
                validations.add("matches current regression expectation");
            }
            else {
                expectedStatus = "changed from " + expected + " to " + match.resolvedAddress;
                validations.add("does not match current regression expectation");
            }
        }

        if (match.pattern.indexOf('^') >= 0) {
            validations.add("pattern marks BytesToSkip with ^");
        }

        return new RecoveryResult(offsetName, staticLabel, sourceLabel, anchor, stringReferenceAddress, xrefFunction,
            sourceFunction, callDepth, match, Math.min(score, 100), expectedStatus, scoreReasons, validations);
    }

    private String confidenceLabel(int score) {
        if (score >= HIGH_CONFIDENCE) {
            return "high";
        }
        if (score >= 65) {
            return "medium";
        }
        return "low";
    }

    private interface OffsetRecipe {
        String name();
        String failureReason();
        List<RecoveryResult> recoverCandidates() throws Exception;
    }

    private interface AnchorScanner {
        PatternMatch scan(Function xrefFunction, Address stringReferenceAddress) throws Exception;
    }

    private class GameStatesRecipe implements OffsetRecipe {
        private final AnchorSpec[] anchors = new AnchorSpec[] {
            AnchorSpec.exact("Unable to get InGameState"),
            AnchorSpec.contains("InGameState")
        };

        @Override
        public String name() {
            return "Game States";
        }

        @Override
        public String failureReason() {
            return "anchor string, XREF caller, or provider null-check was not found.";
        }

        @Override
        public List<RecoveryResult> recoverCandidates() throws Exception {
            List<RecoveryResult> candidates = new ArrayList<>();
            for (StringHit anchor : findAnchors(anchors)) {
                for (Reference reference : referencesTo(anchor.address)) {
                    Function xrefFunction = getFunctionContaining(reference.getFromAddress());
                    if (xrefFunction == null) {
                        continue;
                    }

                    for (Function providerFunction : directCallsBefore(xrefFunction, reference.getFromAddress())) {
                        PatternMatch match = findStaticQwordNullCheck(providerFunction);
                        if (match == null) {
                            continue;
                        }

                        List<String> reasons = new ArrayList<>();
                        List<String> validations = new ArrayList<>();
                        int score = 30;
                        reasons.add("anchor string reached provider call before error branch");
                        score += proximityScore(providerFunction.getEntryPoint(), match.instructionAddress, 0x40, 25,
                            "null-check", reasons);
                        if (providerFunction.getEntryPoint().compareTo(xrefFunction.getEntryPoint()) < 0) {
                            score += 10;
                            reasons.add("provider is a lower-address helper function");
                        }
                        score += refsToScore(match.resolvedAddress, 15, reasons, validations);
                        if (match.pattern.startsWith("48 8B F1 33 ED")) {
                            score += 10;
                            reasons.add("matched known Game States prologue context");
                        }
                        validations.add("provider function: " + formatFunction(providerFunction));

                        candidates.add(buildResult(
                            name(),
                            "GameStates_Static",
                            "GameStatesProvider",
                            "144048458",
                            anchor,
                            reference.getFromAddress(),
                            xrefFunction,
                            providerFunction,
                            -1,
                            match,
                            score,
                            reasons,
                            validations
                        ));
                    }
                }
            }
            return candidates;
        }
    }

    private class FileRootRecipe implements OffsetRecipe {
        private final AnchorSpec[] anchors = new AnchorSpec[] {
            AnchorSpec.fileName("Mods.dat")
        };

        @Override
        public String name() {
            return "File Root";
        }

        @Override
        public String failureReason() {
            return "anchor string, XREF call chain, or static return was not found.";
        }

        @Override
        public List<RecoveryResult> recoverCandidates() throws Exception {
            List<RecoveryResult> candidates = new ArrayList<>();
            for (StringHit anchor : findAnchors(anchors)) {
                for (Reference reference : referencesTo(anchor.address)) {
                    Function xrefFunction = getFunctionContaining(reference.getFromAddress());
                    if (xrefFunction == null) {
                        continue;
                    }

                    for (Function candidateFunction : directCallsToDepth(xrefFunction, 2)) {
                        PatternMatch match = findStaticQwordReturn(candidateFunction);
                        if (match == null) {
                            continue;
                        }

                        int depth = callDepth(xrefFunction, candidateFunction, 2);
                        List<String> reasons = new ArrayList<>();
                        List<String> validations = new ArrayList<>();
                        int score = 35;
                        reasons.add("found static return through file-path XREF call chain");
                        if (depth == 1) {
                            score += 20;
                            reasons.add("finder is a direct call from XREF function");
                        }
                        else if (depth == 2) {
                            score += 15;
                            reasons.add("finder is one nested call from XREF function");
                        }
                        score += proximityScore(candidateFunction.getEntryPoint(), match.instructionAddress, 0x90, 15,
                            "static return", reasons);
                        score += refsToScore(match.resolvedAddress, 15, reasons, validations);
                        if (match.pattern.startsWith("48 83 EC 28 65 48")) {
                            score += 15;
                            reasons.add("matched FileRootFinder TLS-init context");
                        }
                        validations.add("finder function: " + formatFunction(candidateFunction));

                        candidates.add(buildResult(
                            name(),
                            "FileRoot_Static",
                            "FileRootFinder",
                            "1441829C8",
                            anchor,
                            reference.getFromAddress(),
                            xrefFunction,
                            candidateFunction,
                            depth,
                            match,
                            score,
                            reasons,
                            validations
                        ));
                    }
                }
            }
            return candidates;
        }
    }

    private class AreaChangeCounterRecipe implements OffsetRecipe {
        private final OffsetRecipe delegate;

        AreaChangeCounterRecipe() {
            delegate = new AnchorRecipeBuilder("AreaChangeCounter")
                .anchors(
                    AnchorSpec.exact("Got Instance Details from login server"),
                    AnchorSpec.contains("Instance Details from login server")
                )
                .expectedAddress("14347CF48")
                .staticLabel("AreaChangeCounter_Static")
                .sourceLabel("HandleLoginServerInstanceDetails")
                .scanner(new AnchorScanner() {
                    @Override
                    public PatternMatch scan(Function xrefFunction, Address stringReferenceAddress) throws Exception {
                        return findDwordIncrementAfter(xrefFunction, stringReferenceAddress);
                    }
                })
                .scoreBase(45)
                .scanProximity(0x180, 25)
                .contextPrefix("65 48 8B", 20, "matched area-change TLS-init context")
                .build();
        }

        @Override
        public String name() {
            return delegate.name();
        }

        @Override
        public String failureReason() {
            return delegate.failureReason();
        }

        @Override
        public List<RecoveryResult> recoverCandidates() throws Exception {
            return delegate.recoverCandidates();
        }
    }

    private class AnchorRecipeBuilder {
        private final String name;
        private AnchorSpec[] anchors = new AnchorSpec[0];
        private String expectedAddress;
        private String staticLabel;
        private String sourceLabel;
        private AnchorScanner scanner;
        private int scoreBase = 40;
        private long scanProximityBytes = 0;
        private int scanProximityScore = 0;
        private String contextPrefix;
        private int contextScore = 0;
        private String contextReason = "matched context";

        AnchorRecipeBuilder(String name) {
            this.name = name;
        }

        AnchorRecipeBuilder anchors(AnchorSpec... anchors) {
            this.anchors = anchors;
            return this;
        }

        AnchorRecipeBuilder expectedAddress(String expectedAddress) {
            this.expectedAddress = expectedAddress;
            return this;
        }

        AnchorRecipeBuilder staticLabel(String staticLabel) {
            this.staticLabel = staticLabel;
            return this;
        }

        AnchorRecipeBuilder sourceLabel(String sourceLabel) {
            this.sourceLabel = sourceLabel;
            return this;
        }

        AnchorRecipeBuilder scanner(AnchorScanner scanner) {
            this.scanner = scanner;
            return this;
        }

        AnchorRecipeBuilder scoreBase(int scoreBase) {
            this.scoreBase = scoreBase;
            return this;
        }

        AnchorRecipeBuilder scanProximity(long scanProximityBytes, int scanProximityScore) {
            this.scanProximityBytes = scanProximityBytes;
            this.scanProximityScore = scanProximityScore;
            return this;
        }

        AnchorRecipeBuilder contextPrefix(String contextPrefix, int contextScore, String contextReason) {
            this.contextPrefix = contextPrefix;
            this.contextScore = contextScore;
            this.contextReason = contextReason;
            return this;
        }

        OffsetRecipe build() {
            return new OffsetRecipe() {
                @Override
                public String name() {
                    return name;
                }

                @Override
                public String failureReason() {
                    return "anchor string, XREF function, or scanner match was not found.";
                }

                @Override
                public List<RecoveryResult> recoverCandidates() throws Exception {
                    List<RecoveryResult> candidates = new ArrayList<>();
                    for (StringHit anchor : findAnchors(anchors)) {
                        for (Reference reference : referencesTo(anchor.address)) {
                            Function xrefFunction = getFunctionContaining(reference.getFromAddress());
                            if (xrefFunction == null || scanner == null) {
                                continue;
                            }

                            PatternMatch match = scanner.scan(xrefFunction, reference.getFromAddress());
                            if (match == null) {
                                continue;
                            }

                            List<String> reasons = new ArrayList<>();
                            List<String> validations = new ArrayList<>();
                            int score = scoreBase;
                            reasons.add("found scanner match after anchor XREF");
                            if (scanProximityBytes > 0) {
                                score += proximityScore(reference.getFromAddress(), match.instructionAddress,
                                    scanProximityBytes, scanProximityScore, "match", reasons);
                            }
                            if (contextPrefix != null && match.pattern.startsWith(contextPrefix)) {
                                score += contextScore;
                                reasons.add(contextReason);
                            }
                            if (xrefFunction.getBody().contains(match.instructionAddress)) {
                                score += 10;
                                validations.add("match remains inside XREF function body");
                            }

                            candidates.add(buildResult(
                                name,
                                staticLabel,
                                sourceLabel,
                                expectedAddress,
                                anchor,
                                reference.getFromAddress(),
                                xrefFunction,
                                xrefFunction,
                                0,
                                match,
                                score,
                                reasons,
                                validations
                            ));
                        }
                    }
                    return candidates;
                }
            };
        }
    }

    private static class AnchorSpec {
        final String value;
        final MatchType matchType;

        private AnchorSpec(String value, MatchType matchType) {
            this.value = value;
            this.matchType = matchType;
        }

        static AnchorSpec exact(String value) {
            return new AnchorSpec(value, MatchType.EXACT);
        }

        static AnchorSpec contains(String value) {
            return new AnchorSpec(value, MatchType.CONTAINS);
        }

        static AnchorSpec fileName(String value) {
            return new AnchorSpec(value, MatchType.FILE_NAME);
        }

        boolean matches(String candidate) {
            if (matchType == MatchType.EXACT) {
                return value.equals(candidate);
            }
            if (matchType == MatchType.CONTAINS) {
                return candidate.contains(value);
            }

            return value.equals(lastPathComponent(candidate));
        }

        private String lastPathComponent(String candidate) {
            int slash = candidate.lastIndexOf('/');
            int backslash = candidate.lastIndexOf('\\');
            int separator = Math.max(slash, backslash);
            return separator >= 0 ? candidate.substring(separator + 1) : candidate;
        }
    }

    private enum MatchType {
        EXACT,
        CONTAINS,
        FILE_NAME
    }

    private static class StringHit {
        final String value;
        final Address address;

        StringHit(String value, Address address) {
            this.value = value;
            this.address = address;
        }
    }

    private static class FunctionDepth {
        final Function function;
        final int depth;

        FunctionDepth(Function function, int depth) {
            this.function = function;
            this.depth = depth;
        }
    }

    private static class RecoveryResult {
        final String offsetName;
        final String staticLabel;
        final String sourceLabel;
        final StringHit anchor;
        final Address stringReferenceAddress;
        final Function xrefFunction;
        final Function sourceFunction;
        final int callDepth;
        final PatternMatch match;
        final int score;
        final String expectedStatus;
        final List<String> scoreReasons;
        final List<String> validations;

        RecoveryResult(String offsetName, String staticLabel, String sourceLabel, StringHit anchor,
                Address stringReferenceAddress, Function xrefFunction, Function sourceFunction, int callDepth,
                PatternMatch match, int score, String expectedStatus, List<String> scoreReasons,
                List<String> validations) {
            this.offsetName = offsetName;
            this.staticLabel = staticLabel;
            this.sourceLabel = sourceLabel;
            this.anchor = anchor;
            this.stringReferenceAddress = stringReferenceAddress;
            this.xrefFunction = xrefFunction;
            this.sourceFunction = sourceFunction;
            this.callDepth = callDepth;
            this.match = match;
            this.score = score;
            this.expectedStatus = expectedStatus;
            this.scoreReasons = scoreReasons;
            this.validations = validations;
        }

    }

    private static class PatternMatch {
        final Address patternAddress;
        final Address instructionAddress;
        final Address resolvedAddress;
        final String pattern;
        final int bytesToSkip;
        final String instructionKind;

        PatternMatch(Address patternAddress, Address instructionAddress, Address resolvedAddress,
                String pattern, int bytesToSkip, String instructionKind) {
            this.patternAddress = patternAddress;
            this.instructionAddress = instructionAddress;
            this.resolvedAddress = resolvedAddress;
            this.pattern = pattern;
            this.bytesToSkip = bytesToSkip;
            this.instructionKind = instructionKind;
        }
    }

    private class RecoverySummary {
        private final List<RecoveryResult> successes = new ArrayList<>();
        private final List<String> failures = new ArrayList<>();
        private final List<Integer> candidateCounts = new ArrayList<>();

        void addSuccess(RecoveryResult result, int candidateCount) {
            successes.add(result);
            candidateCounts.add(candidateCount);
        }

        void addFailure(String name, String reason) {
            failures.add(name + ": " + reason);
        }

        void print() {
            println("== Summary ==");
            println("Recovered: " + successes.size() + " / " + (successes.size() + failures.size()));

            for (int i = 0; i < successes.size(); i++) {
                RecoveryResult result = successes.get(i);
                println("  OK   " + result.offsetName
                    + " -> " + result.match.resolvedAddress
                    + " [" + confidenceLabel(result.score) + ", candidates=" + candidateCounts.get(i) + "]");
            }

            for (String failure : failures) {
                println("  FAIL " + failure);
            }
        }
    }
}
