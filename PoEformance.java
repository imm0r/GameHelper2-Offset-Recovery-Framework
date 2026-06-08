// Ghidra script: recover update-prone static offsets from semantic recipes.
// @category PoEformance
// @author Arsenic

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
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

public class PoEformance extends GhidraScript {
    private static final boolean VERBOSE = false;
    private static final int HIGH_CONFIDENCE = 85;
    private static final int MAX_GAME_STATES_PROVIDER_SCAN_BYTES = 0x180;
    private static final int MAX_FILE_ROOT_FINDER_SCAN_BYTES = 0x180;
    private static final int MAX_AREA_COUNTER_SCAN_BYTES = 0x300;
    private static final int MAX_UNIQUE_PATTERN_BYTES = 0x80;

    private final List<StringHit> stringCache = new ArrayList<>();
    private final RecoverySummary summary = new RecoverySummary();

    @Override
    public void run() throws Exception {
        println("PoEformance - Pattern-Voodoo");
        println("Program: " + currentProgram.getName());
        println("");

        cacheDefinedStrings();

        for (OffsetRecipe recipe : Arrays.asList(
            new GameStatesRecipe(),
            new FileRootRecipe(),
            new AreaChangeCounterRecipe(),
            new TerrainRotatorHelperRecipe(),
            new TerrainRotationSelectorRecipe(),
            new GameCullSizeRecipe()
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
            finalizeOutputPattern(best);
            if (best.match.patternMatchCount != 1) {
                String reason = "output pattern is not unique in executable memory; matches="
                    + best.match.patternMatchCount;
                println("FAILED: " + reason);
                summary.addFailure(recipe.name(), reason);
                return;
            }
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
        println("Match start         : " + result.match.matchAddress);
        println("Target instruction  : " + result.match.instructionAddress + "  " + result.match.matchKind);
        println("Resolved address    : " + result.match.resolvedAddress);
        println("Output pattern      : " + result.match.outputPattern);
        println("BytesToSkip         : " + result.match.bytesToSkip);
        println("Pattern matches     : " + result.match.patternMatchCount);
        println("Confidence          : " + confidenceLabel(result.score) + " (" + result.score + "/100)");

        if (VERBOSE) {
            printList("Score reasons", result.scoreReasons);
            printList("Validations", result.validations);
        }
    }

    private void finalizeOutputPattern(RecoveryResult result) throws MemoryAccessException {
        if (result.match.patternMatchCount == 1) {
            return;
        }

        UniquePattern uniquePattern = makeBestUniquePattern(result.match);
        result.match.matchAddress = uniquePattern.start;
        result.match.outputPattern = uniquePattern.pattern;
        result.match.bytesToSkip = uniquePattern.bytesToSkip;
        result.match.patternMatchCount = uniquePattern.matchCount;
        result.validations.add("SigMaker pass ran on selected candidate only");
        if (uniquePattern.matchCount == 1) {
            result.score = Math.min(100, result.score + 5);
            result.validations.add("output pattern is unique in executable memory");
        }
        else {
            result.score = 0;
            result.validations.add("output pattern match count: " + uniquePattern.matchCount);
        }
    }

    private UniquePattern makeBestUniquePattern(OffsetMatch match) throws MemoryAccessException {
        int minimumLength = parsePattern(match.outputPattern).bytes.length;
        int originalInstructionOffset = (int)match.instructionAddress.subtract(match.matchAddress);
        int displacementOffsetInInstruction = match.bytesToSkip - originalInstructionOffset;
        int originalTailLength = minimumLength - originalInstructionOffset;

        UniquePattern best = null;
        for (Address start : uniquePatternStartCandidates(match)) {
            if (start == null || start.compareTo(match.instructionAddress) > 0) {
                continue;
            }

            int instructionOffset = (int)match.instructionAddress.subtract(start);
            int bytesToSkip = instructionOffset + displacementOffsetInInstruction;
            int candidateMinimumLength = Math.max(instructionOffset + originalTailLength, bytesToSkip + 4);
            if (bytesToSkip < 0 || candidateMinimumLength > MAX_UNIQUE_PATTERN_BYTES) {
                continue;
            }

            UniquePattern candidate = makeUniquePattern(start, candidateMinimumLength, bytesToSkip);
            if (best == null || candidate.isBetterThan(best)) {
                best = candidate;
            }
            if (candidate.matchCount == 1 && candidate.byteLength <= minimumLength) {
                return candidate;
            }
        }

        if (best != null) {
            return best;
        }
        return makeUniquePattern(match.matchAddress, minimumLength, match.bytesToSkip);
    }

    private List<Address> uniquePatternStartCandidates(OffsetMatch match) {
        List<Address> starts = new ArrayList<>();
        Set<Address> seen = new HashSet<>();
        addUniqueStart(starts, seen, match.matchAddress);
        addUniqueStart(starts, seen, match.instructionAddress);

        Function function = getFunctionContaining(match.instructionAddress);
        Instruction instruction = getInstructionBefore(match.instructionAddress);
        int count = 0;
        while (instruction != null
            && count < 16
            && match.instructionAddress.subtract(instruction.getAddress()) <= 0x60
            && (function == null || function.getBody().contains(instruction.getAddress()))) {
            addUniqueStart(starts, seen, instruction.getAddress());
            instruction = getInstructionBefore(instruction);
            count++;
        }

        if (function != null && hasInstructionBody(function)) {
            addUniqueStart(starts, seen, function.getEntryPoint());
        }
        return starts;
    }

    private void addUniqueStart(List<Address> starts, Set<Address> seen, Address address) {
        if (address != null && !seen.contains(address)) {
            starts.add(address);
            seen.add(address);
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
            + result.match.resolvedAddress + " via " + result.match.matchKind + ".";

        setEOLComment(result.match.instructionAddress, comment);
        createBookmark(result.anchor.address, BookmarkType.ANALYSIS,
            "PoEformance Offset: " + result.offsetName + " anchor string.");
        createBookmark(result.stringReferenceAddress, BookmarkType.ANALYSIS,
            "PoEformance Offset: " + result.offsetName + " anchor XREF.");
        createBookmark(result.match.instructionAddress, BookmarkType.ANALYSIS, "PoEformance Offset: " + comment);
        createBookmark(result.match.resolvedAddress, BookmarkType.ANALYSIS,
            "PoEformance Offset: " + result.offsetName + " static candidate.");

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

    private int callerCount(Function function) {
        if (function == null) {
            return 0;
        }

        int count = 0;
        for (Reference reference : getReferencesTo(function.getEntryPoint())) {
            if (reference.getReferenceType().isCall()) {
                count++;
            }
        }
        return count;
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

    private OffsetMatch findStaticQwordNullCheck(Function function) throws Exception {
        for (Instruction instruction : instructionsInWindow(
            function,
            function.getEntryPoint(),
            MAX_GAME_STATES_PROVIDER_SCAN_BYTES
        )) {
            Address address = instruction.getAddress();
            if (isStaticQwordNullCheck(instruction)) {
                boolean hasPrologueContext = hasPreviousInstructionText(function, address, "XOR EBP,EBP");
                return ripRelativeMatchThroughBranch(
                    function,
                    instruction,
                    3,
                    "static qword null-check",
                    hasPrologueContext ? "provider-prologue" : null
                );
            }
        }
        return null;
    }

    private OffsetMatch findStaticQwordReturn(Function function) throws Exception {
        for (Instruction instruction : instructionsInWindow(
            function,
            function.getEntryPoint(),
            MAX_FILE_ROOT_FINDER_SCAN_BYTES
        )) {
            Address address = instruction.getAddress();
            if (!isStaticMovIntoRax(instruction) || !hasNearbyRet(address, 0x18)) {
                continue;
            }

            boolean hasTlsInitContext = hasThreadLocalSetupNearEntry(function)
                && address.subtract(function.getEntryPoint()) < 0x80;
            if (!hasTlsInitContext) {
                continue;
            }
            return ripRelativeMatch(
                address,
                instruction,
                3,
                "static qword return",
                hasTlsInitContext ? "tls-init-context" : null
            );
        }
        return null;
    }

    private OffsetMatch findDwordIncrementAfter(Function function, Address anchorReference) throws Exception {
        for (Instruction instruction : instructionsInWindow(function, anchorReference, MAX_AREA_COUNTER_SCAN_BYTES)) {
            Address address = instruction.getAddress();
            if (!isStaticDwordIncrement(instruction)) {
                continue;
            }

            boolean hasTlsContext = hasAreaChangeTlsContext(function, address);
            return ripRelativeMatch(
                address,
                instruction,
                2,
                "static dword increment",
                hasTlsContext ? "tls-init-context" : null
            );
        }
        return null;
    }

    private List<OffsetMatch> findGameCullSizeShapeMatches() throws Exception {
        List<OffsetMatch> matches = new ArrayList<>();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(
            currentProgram.getMemory().getExecuteSet(),
            true
        );

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            Address address = instruction.getAddress();
            if (!isStaticSubFromEax(instruction)) {
                continue;
            }

            Address staticReference = firstMemoryReferenceFrom(instruction);
            if (staticReference == null || !hasCallBefore(address, 0x80) || !hasVectorZeroAfter(address, 0x40)) {
                continue;
            }

            matches.add(ripRelativeMatch(
                address,
                instruction,
                2,
                "game cull size subtract from FOO result",
                "call-before",
                "vector-zero-after"
            ));
        }
        return matches;
    }

    private boolean isStaticQwordNullCheck(Instruction instruction) {
        if (!"CMP".equals(instruction.getMnemonicString()) || firstMemoryReferenceFrom(instruction) == null) {
            return false;
        }

        String text = instruction.toString().toUpperCase();
        return text.indexOf("QWORD PTR") >= 0
            && (text.endsWith(",RBP") || text.endsWith(",0X0") || text.endsWith(",0"));
    }

    private boolean isStaticMovIntoRax(Instruction instruction) {
        if (!"MOV".equals(instruction.getMnemonicString()) || firstMemoryReferenceFrom(instruction) == null) {
            return false;
        }

        return instruction.toString().toUpperCase().startsWith("MOV RAX,");
    }

    private boolean isStaticDwordIncrement(Instruction instruction) {
        if (!"INC".equals(instruction.getMnemonicString()) || firstMemoryReferenceFrom(instruction) == null) {
            return false;
        }

        return instruction.toString().toUpperCase().indexOf("DWORD PTR") >= 0;
    }

    private boolean isStaticSubFromEax(Instruction instruction) {
        if (!"SUB".equals(instruction.getMnemonicString())) {
            return false;
        }

        String text = instruction.toString().toUpperCase();
        return text.startsWith("SUB EAX,") && firstMemoryReferenceFrom(instruction) != null;
    }

    private OffsetMatch ripRelativeMatch(Address matchStart, Instruction instruction, int displacementOffset,
            String matchKind, String... traits) throws Exception {
        int patternLength = (int)instruction.getAddress().subtract(matchStart) + instruction.getLength();
        return ripRelativeMatch(matchStart, instruction, displacementOffset, patternLength, matchKind, traits);
    }

    private OffsetMatch ripRelativeMatch(Address matchStart, Instruction instruction, int displacementOffset,
            int patternLength, String matchKind, String... traits) throws Exception {
        Address instructionAddress = instruction.getAddress();
        Address resolved = firstMemoryReferenceFrom(instruction);
        if (resolved == null) {
            resolved = resolveRipRelative(instructionAddress, instruction.getLength(), displacementOffset);
        }

        int bytesToSkip = (int)instructionAddress.subtract(matchStart) + displacementOffset;
        return new OffsetMatch(
            matchStart,
            instructionAddress,
            resolved,
            ripPattern(matchStart, patternLength, bytesToSkip, 4),
            bytesToSkip,
            matchKind,
            0,
            traits
        );
    }

    private OffsetMatch ripRelativeMatchThroughBranch(Function function, Instruction instruction, int displacementOffset,
            String matchKind, String... traits) throws Exception {
        int length = instruction.getLength();
        Instruction next = getInstructionAfter(instruction);
        if (next != null
            && function.getBody().contains(next.getAddress())
            && next.getFlowType().isConditional()) {
            length += next.getLength();
        }

        return ripRelativeMatch(instruction.getAddress(), instruction, displacementOffset, length, matchKind, traits);
    }

    private UniquePattern makeUniquePattern(Address start, int minimumLength, int bytesToSkip)
            throws MemoryAccessException {
        Function function = getFunctionContaining(start);
        int length = alignPatternLengthToInstruction(start, minimumLength, function);
        UniquePattern best = null;

        while (length <= MAX_UNIQUE_PATTERN_BYTES) {
            String pattern = ripPattern(start, length, bytesToSkip, 4);
            PatternBytes parsed = parsePattern(pattern);
            int matchCount = countExecutableMatches(parsed, 2);
            UniquePattern candidate = new UniquePattern(
                pattern,
                matchCount,
                start,
                bytesToSkip,
                parsed.bytes.length,
                parsed.fixedByteCount
            );
            if (best == null || candidate.isBetterThan(best)) {
                best = candidate;
            }
            if (matchCount == 1) {
                return candidate;
            }

            int nextLength = nextInstructionAlignedLength(start, length, function);
            if (nextLength <= length) {
                break;
            }
            length = nextLength;
        }

        if (best != null) {
            return best;
        }

        String pattern = ripPattern(start, minimumLength, bytesToSkip, 4);
        PatternBytes parsed = parsePattern(pattern);
        return new UniquePattern(
            pattern,
            countExecutableMatches(parsed, 2),
            start,
            bytesToSkip,
            parsed.bytes.length,
            parsed.fixedByteCount
        );
    }

    private int alignPatternLengthToInstruction(Address start, int minimumLength, Function function) {
        int alignedLength = 0;
        Instruction instruction = getInstructionAt(start);
        if (instruction == null) {
            instruction = getInstructionAfter(start);
        }

        while (instruction != null
            && instruction.getAddress().compareTo(start) >= 0
            && (function == null || function.getBody().contains(instruction.getAddress()))
            && alignedLength < minimumLength) {
            alignedLength = (int)instruction.getAddress().subtract(start) + instruction.getLength();
            instruction = getInstructionAfter(instruction);
        }

        return Math.max(minimumLength, alignedLength);
    }

    private int nextInstructionAlignedLength(Address start, int currentLength, Function function) {
        Address currentEnd = start.add(currentLength - 1);
        Instruction instruction = getInstructionAfter(currentEnd);
        if (instruction == null || (function != null && !function.getBody().contains(instruction.getAddress()))) {
            return -1;
        }

        return (int)instruction.getAddress().subtract(start) + instruction.getLength();
    }

    private String ripPattern(Address start, int length, int displacementOffset, int displacementLength)
            throws MemoryAccessException {
        boolean[] wildcard = new boolean[length];
        markWildcard(wildcard, displacementOffset, displacementLength);
        markReferencedDisplacements(start, length, wildcard);

        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < length; i++) {
            if (i > 0) {
                builder.append(' ');
            }
            if (i == displacementOffset) {
                builder.append("^ ");
            }
            if (wildcard[i]) {
                builder.append("??");
            }
            else {
                builder.append(String.format("%02X", u8(start.add(i))));
            }
        }
        return builder.toString();
    }

    private void markReferencedDisplacements(Address start, int length, boolean[] wildcard)
            throws MemoryAccessException {
        Address end = start.add(length - 1);
        Instruction instruction = getInstructionAt(start);
        if (instruction == null) {
            instruction = getInstructionAfter(start);
        }

        while (instruction != null
            && instruction.getAddress().compareTo(end) <= 0
            && instruction.getAddress().compareTo(start) >= 0) {
            for (Reference reference : getReferencesFrom(instruction.getAddress())) {
                Address toAddress = reference.getToAddress();
                if (isRelocatableReference(reference)
                    && toAddress != null
                    && currentProgram.getMemory().contains(toAddress)) {
                    markDisplacementBytes(start, instruction, toAddress, wildcard);
                }
            }
            instruction = getInstructionAfter(instruction);
        }
    }

    private boolean isRelocatableReference(Reference reference) {
        if (reference.isMemoryReference()) {
            return true;
        }

        RefType type = reference.getReferenceType();
        return type.isCall() || type.isJump() || type.isFlow();
    }

    private void markDisplacementBytes(Address patternStart, Instruction instruction, Address target, boolean[] wildcard)
            throws MemoryAccessException {
        long nextInstructionOffset = instruction.getAddress().getOffset() + instruction.getLength();
        int displacement = (int)(target.getOffset() - nextInstructionOffset);
        int instructionOffset = (int)instruction.getAddress().subtract(patternStart);

        for (int i = 0; i <= instruction.getLength() - 4; i++) {
            if (u8(instruction.getAddress().add(i)) == (displacement & 0xff)
                && u8(instruction.getAddress().add(i + 1)) == ((displacement >>> 8) & 0xff)
                && u8(instruction.getAddress().add(i + 2)) == ((displacement >>> 16) & 0xff)
                && u8(instruction.getAddress().add(i + 3)) == ((displacement >>> 24) & 0xff)) {
                markWildcard(wildcard, instructionOffset + i, 4);
                return;
            }
        }
    }

    private void markWildcard(boolean[] wildcard, int offset, int length) {
        for (int i = Math.max(0, offset); i < offset + length && i < wildcard.length; i++) {
            wildcard[i] = true;
        }
    }

    private PatternBytes parsePattern(String pattern) {
        String[] parts = pattern.replace("^", "").trim().split("\\s+");
        byte[] bytes = new byte[parts.length];
        boolean[] mask = new boolean[parts.length];

        for (int i = 0; i < parts.length; i++) {
            if (parts[i].startsWith("?")) {
                bytes[i] = 0;
                mask[i] = false;
            }
            else {
                bytes[i] = (byte)Integer.parseInt(parts[i], 16);
                mask[i] = true;
            }
        }

        return new PatternBytes(bytes, mask);
    }

    private int countExecutableMatches(PatternBytes pattern, int stopAfter) throws MemoryAccessException {
        if (pattern.firstMaskedIndex < 0) {
            return stopAfter;
        }

        int count = 0;
        byte[] searchMask = searchMask(pattern.mask);
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isExecute() || !block.isInitialized() || block.getSize() < pattern.bytes.length) {
                continue;
            }

            Address cursor = block.getStart();
            Address lastStart = block.getStart().add(block.getSize() - pattern.bytes.length);
            while (cursor.compareTo(lastStart) <= 0 && !monitor.isCancelled()) {
                Address found = currentProgram.getMemory().findBytes(
                    cursor,
                    block.getEnd(),
                    pattern.bytes,
                    searchMask,
                    true,
                    monitor
                );
                if (found == null || found.compareTo(lastStart) > 0) {
                    break;
                }
                count++;
                if (count >= stopAfter) {
                    return count;
                }
                cursor = found.add(1);
            }
        }
        return count;
    }

    private byte[] searchMask(boolean[] fixedBytes) {
        byte[] mask = new byte[fixedBytes.length];
        for (int i = 0; i < fixedBytes.length; i++) {
            if (fixedBytes[i]) {
                mask[i] = (byte)0xff;
            }
        }
        return mask;
    }

    private Address firstMemoryReferenceFrom(Instruction instruction) {
        for (Reference reference : getReferencesFrom(instruction.getAddress())) {
            Address toAddress = reference.getToAddress();
            if (reference.isMemoryReference()
                && toAddress != null
                && currentProgram.getMemory().contains(toAddress)) {
                return toAddress;
            }
        }
        return null;
    }

    private boolean hasCallBefore(Address address, int maxBytes) {
        Function function = getFunctionContaining(address);
        if (!hasInstructionBody(function)) {
            return false;
        }

        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            Address instructionAddress = instruction.getAddress();
            if (instructionAddress.compareTo(address) >= 0) {
                break;
            }
            if ("CALL".equals(instruction.getMnemonicString()) && address.subtract(instructionAddress) <= maxBytes) {
                return true;
            }
        }
        return false;
    }

    private boolean hasPreviousInstructionText(Function function, Address address, String expectedText) {
        Instruction instruction = getInstructionBefore(address);
        return instruction != null
            && function.getBody().contains(instruction.getAddress())
            && instruction.toString().toUpperCase().equals(expectedText);
    }

    private boolean hasVectorZeroAfter(Address address, int maxBytes) {
        Instruction instruction = getInstructionAfter(address);
        while (instruction != null && instruction.getAddress().subtract(address) <= maxBytes) {
            String mnemonic = instruction.getMnemonicString();
            String text = instruction.toString().toUpperCase();
            if (("XORPS".equals(mnemonic) || "PXOR".equals(mnemonic) || "XORPD".equals(mnemonic))
                && text.indexOf("XMM") >= 0) {
                return true;
            }
            instruction = getInstructionAfter(instruction);
        }
        return false;
    }

    private List<OffsetMatch> findTerrainRotatorHelperShapeMatches() throws Exception {
        return findTerrainRotationShapeMatches(false);
    }

    private List<OffsetMatch> findTerrainRotationSelectorShapeMatches() throws Exception {
        return findTerrainRotationShapeMatches(true);
    }

    private List<OffsetMatch> findTerrainRotationShapeMatches(boolean selector) throws Exception {
        List<OffsetMatch> matches = new ArrayList<>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!hasInstructionBody(function)) {
                continue;
            }

            OffsetMatch match = inspectTerrainRotationShape(function, selector);
            if (match != null) {
                matches.add(match);
            }
        }
        return matches;
    }

    private OffsetMatch inspectTerrainRotationShape(Function function, boolean selector) throws Exception {
        List<Instruction> instructions = instructionsInWindow(function, function.getEntryPoint(), 0xc0);
        if (instructions.size() < 40 || instructions.size() > 80) {
            return null;
        }

        Address entry = function.getEntryPoint();
        if (!hasTerrainHelperEntryShape(instructions)) {
            return null;
        }

        Instruction tableLea = null;
        Instruction rotatorLea = null;
        boolean hasClampEight = false;
        boolean hasTileSizeConstant = false;
        boolean hasScaleByThree = false;
        boolean hasBoundsCheck = false;
        boolean hasTerrainReadCall = false;

        for (Instruction instruction : instructions) {
            Address address = instruction.getAddress();
            String text = instruction.toString().toUpperCase();
            if (isStaticLeaInto(instruction, "RCX")) {
                tableLea = instruction;
            }
            if (isStaticLeaInto(instruction, "RAX")) {
                rotatorLea = instruction;
            }
            if ("MOV EAX,0X8".equals(text) || "CMP R8D,EAX".equals(text)) {
                hasClampEight = true;
            }
            if ("MOV EDX,0X16".equals(text)) {
                hasTileSizeConstant = true;
            }
            if ("LEA".equals(instruction.getMnemonicString())
                && text.startsWith("LEA R8,")
                && text.indexOf("R8*0X2") >= 0) {
                hasScaleByThree = true;
            }
            if (text.indexOf("0X17") >= 0) {
                hasBoundsCheck = true;
            }
            if ("CALL".equals(instruction.getMnemonicString()) && address.subtract(entry) > 0x80) {
                hasTerrainReadCall = true;
            }
        }

        if (tableLea == null || rotatorLea == null || !hasClampEight || !hasTileSizeConstant
            || !hasScaleByThree || !hasBoundsCheck || !hasTerrainReadCall) {
            return null;
        }

        if (selector) {
            return ripRelativeMatch(
                entry,
                tableLea,
                3,
                "terrain rotation selector function shape"
            );
        }

        return ripRelativeMatch(
            entry,
            rotatorLea,
            3,
            "terrain rotator helper function shape"
        );
    }

    private boolean hasTerrainHelperEntryShape(List<Instruction> instructions) {
        if (instructions.size() < 4) {
            return false;
        }

        return instructionTextEquals(instructions.get(0), "SUB RSP,0x38")
            && instructionTextEquals(instructions.get(1), "MOVZX EAX,R8B")
            && instructionTextEquals(instructions.get(2), "MOV R10,RCX")
            && instructionTextEquals(instructions.get(3), "MOV R9,RDX");
    }

    private boolean isStaticLeaInto(Instruction instruction, String register) {
        if (!"LEA".equals(instruction.getMnemonicString()) || firstMemoryReferenceFrom(instruction) == null) {
            return false;
        }

        return instruction.toString().toUpperCase().startsWith("LEA " + register + ",");
    }

    private boolean instructionTextEquals(Instruction instruction, String expected) {
        return instruction.toString().toUpperCase().equals(expected.toUpperCase());
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

    private boolean hasThreadLocalSetupNearEntry(Function function) {
        for (Instruction instruction : instructionsInWindow(function, function.getEntryPoint(), 0x40)) {
            if (isThreadLocalAccess(instruction)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasAreaChangeTlsContext(Function function, Address incrementAddress) {
        for (Instruction instruction : instructionsInWindow(function, function.getEntryPoint(), MAX_AREA_COUNTER_SCAN_BYTES)) {
            Address address = instruction.getAddress();
            if (address.compareTo(incrementAddress) >= 0) {
                break;
            }
            if (incrementAddress.subtract(address) <= 0x80 && isThreadLocalAccess(instruction)) {
                return true;
            }
        }
        return false;
    }

    private boolean isThreadLocalAccess(Instruction instruction) {
        String text = instruction.toString().toUpperCase();
        return (text.indexOf("GS:") >= 0 || text.indexOf("FS:") >= 0)
            && text.indexOf("0X58") >= 0;
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

    private int u8(Address address) throws MemoryAccessException {
        return getByte(address) & 0xff;
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
            StringHit anchor, Address stringReferenceAddress, Function xrefFunction,
            Function sourceFunction, int callDepth, OffsetMatch match, int score, List<String> scoreReasons,
            List<String> validations) {
        if (match.outputPattern.indexOf('^') >= 0) {
            validations.add("pattern marks BytesToSkip with ^");
        }
        if (match.patternMatchCount == 1) {
            validations.add("output pattern is unique in executable memory");
            score += 5;
        }
        else {
            validations.add("output pattern match count: " + match.patternMatchCount);
            score -= 15;
        }

        return new RecoveryResult(offsetName, staticLabel, sourceLabel, anchor, stringReferenceAddress, xrefFunction,
            sourceFunction, callDepth, match, Math.max(0, Math.min(score, 100)), scoreReasons, validations);
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
        OffsetMatch scan(Function xrefFunction, Address stringReferenceAddress) throws Exception;
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
                        OffsetMatch match = findStaticQwordNullCheck(providerFunction);
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
                        if (match.hasTrait("provider-prologue")) {
                            score += 10;
                            reasons.add("matched provider prologue context");
                        }
                        validations.add("provider function: " + formatFunction(providerFunction));

                        candidates.add(buildResult(
                            name(),
                            "GameStates_Static",
                            "GameStatesProvider",
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
                        OffsetMatch match = findStaticQwordReturn(candidateFunction);
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
                        if (match.hasTrait("tls-init-context")) {
                            score += 15;
                            reasons.add("matched FileRootFinder TLS-init context");
                        }
                        validations.add("finder function: " + formatFunction(candidateFunction));

                        candidates.add(buildResult(
                            name(),
                            "FileRoot_Static",
                            "FileRootFinder",
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
                .staticLabel("AreaChangeCounter_Static")
                .sourceLabel("HandleLoginServerInstanceDetails")
                .scanner(new AnchorScanner() {
                    @Override
                    public OffsetMatch scan(Function xrefFunction, Address stringReferenceAddress) throws Exception {
                        return findDwordIncrementAfter(xrefFunction, stringReferenceAddress);
                    }
                })
                .scoreBase(45)
                .scanProximity(0x180, 25)
                .contextTrait("tls-init-context", 20, "matched area-change TLS-init context")
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

    private class GameCullSizeRecipe implements OffsetRecipe {
        @Override
        public String name() {
            return "GameCullSize";
        }

        @Override
        public String failureReason() {
            return "FOO-result static subtract shape was not found.";
        }

        @Override
        public List<RecoveryResult> recoverCandidates() throws Exception {
            List<OffsetMatch> matches = findGameCullSizeShapeMatches();
            List<RecoveryResult> candidates = new ArrayList<>();
            StringHit syntheticAnchor = new StringHit("GameCullSize FOO-result subtract shape", currentProgram.getMinAddress());

            for (OffsetMatch match : matches) {
                Function function = getFunctionContaining(match.instructionAddress);
                List<String> reasons = new ArrayList<>();
                List<String> validations = new ArrayList<>();
                int score = 45;

                reasons.add("matched FOO-result static subtract shape");

                if (matches.size() == 1) {
                    score += 30;
                    reasons.add("candidate is unique");
                }
                else {
                    validations.add("candidate hit count: " + matches.size());
                }

                if (hasInstructionBody(function) && function.getBody().contains(match.instructionAddress)) {
                    score += 10;
                    validations.add("match is inside function body: " + formatFunction(function));
                }

                if (callerCount(function) > 0) {
                    score += 10;
                    reasons.add("containing function has direct callers");
                }

                if (hasCallBefore(match.instructionAddress, 0x80)) {
                    score += 15;
                    reasons.add("match follows a nearby function call");
                }

                if (hasVectorZeroAfter(match.instructionAddress, 0x40)) {
                    score += 15;
                    reasons.add("match is followed by vector-zero setup");
                }

                if (getInstructionAt(match.instructionAddress) != null) {
                    score += 5;
                    validations.add("match starts on a decoded instruction");
                }

                candidates.add(buildResult(
                    name(),
                    "GameCullSize_Static",
                    "GameCullSize_Source",
                    syntheticAnchor,
                    match.instructionAddress,
                    function,
                    function,
                    0,
                    match,
                    score,
                    reasons,
                    validations
                ));
            }
            return candidates;
        }
    }

    private class TerrainRotationSelectorRecipe implements OffsetRecipe {
        @Override
        public String name() {
            return "Terrain Rotation Selector";
        }

        @Override
        public String failureReason() {
            return "terrain rotation helper function shape was not found.";
        }

        @Override
        public List<RecoveryResult> recoverCandidates() throws Exception {
            List<OffsetMatch> matches = findTerrainRotationSelectorShapeMatches();
            List<RecoveryResult> candidates = new ArrayList<>();
            StringHit syntheticAnchor = new StringHit("Terrain Rotation Selector function shape", currentProgram.getMinAddress());

            for (OffsetMatch match : matches) {
                Function function = getFunctionContaining(match.instructionAddress);
                List<String> reasons = new ArrayList<>();
                List<String> validations = new ArrayList<>();
                int score = 50;

                score += 20;
                reasons.add("matched Terrain Rotation Selector function shape");

                if (matches.size() == 1) {
                    score += 30;
                    reasons.add("candidate is unique");
                }
                else {
                    validations.add("candidate hit count: " + matches.size());
                }

                if (hasInstructionBody(function) && function.getBody().contains(match.instructionAddress)) {
                    score += 10;
                    validations.add("match is inside function body: " + formatFunction(function));
                }

                if (callerCount(function) == 1) {
                    score += 10;
                    reasons.add("selector helper has a single direct caller");
                }

                if (getInstructionAt(match.instructionAddress) != null) {
                    score += 10;
                    validations.add("match starts on a decoded instruction");
                }

                candidates.add(buildResult(
                    name(),
                    "TerrainRotationSelector_Static",
                    "TerrainRotationSelector_Source",
                    syntheticAnchor,
                    match.instructionAddress,
                    function,
                    function,
                    0,
                    match,
                    score,
                    reasons,
                    validations
                ));
            }
            return candidates;
        }
    }

    private class TerrainRotatorHelperRecipe implements OffsetRecipe {
        @Override
        public String name() {
            return "Terrain Rotator Helper";
        }

        @Override
        public String failureReason() {
            return "terrain rotation helper function shape was not found.";
        }

        @Override
        public List<RecoveryResult> recoverCandidates() throws Exception {
            List<OffsetMatch> matches = findTerrainRotatorHelperShapeMatches();
            List<RecoveryResult> candidates = new ArrayList<>();
            StringHit syntheticAnchor = new StringHit("Terrain Rotator Helper function shape", currentProgram.getMinAddress());

            for (OffsetMatch match : matches) {
                Function function = getFunctionContaining(match.instructionAddress);
                List<String> reasons = new ArrayList<>();
                List<String> validations = new ArrayList<>();
                int score = 50;

                score += 20;
                reasons.add("matched Terrain Rotator helper function shape");

                if (matches.size() == 1) {
                    score += 30;
                    reasons.add("candidate is unique");
                }
                else {
                    validations.add("candidate hit count: " + matches.size());
                }

                if (hasInstructionBody(function) && function.getBody().contains(match.instructionAddress)) {
                    score += 10;
                    validations.add("match is inside function body: " + formatFunction(function));
                }

                if (callerCount(function) == 1) {
                    score += 10;
                    reasons.add("helper has a single direct caller");
                }

                if (getInstructionAt(match.instructionAddress) != null) {
                    score += 10;
                    validations.add("match starts on a decoded instruction");
                }

                candidates.add(buildResult(
                    name(),
                    "TerrainRotatorHelper_Static",
                    "TerrainRotatorHelper_Source",
                    syntheticAnchor,
                    match.instructionAddress,
                    function,
                    function,
                    0,
                    match,
                    score,
                    reasons,
                    validations
                ));
            }
            return candidates;
        }
    }

    private class AnchorRecipeBuilder {
        private final String name;
        private AnchorSpec[] anchors = new AnchorSpec[0];
        private String staticLabel;
        private String sourceLabel;
        private AnchorScanner scanner;
        private int scoreBase = 40;
        private long scanProximityBytes = 0;
        private int scanProximityScore = 0;
        private String contextTrait;
        private int contextScore = 0;
        private String contextReason = "matched context";

        AnchorRecipeBuilder(String name) {
            this.name = name;
        }

        AnchorRecipeBuilder anchors(AnchorSpec... anchors) {
            this.anchors = anchors;
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

        AnchorRecipeBuilder contextTrait(String contextTrait, int contextScore, String contextReason) {
            this.contextTrait = contextTrait;
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

                            OffsetMatch match = scanner.scan(xrefFunction, reference.getFromAddress());
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
                            if (contextTrait != null && match.hasTrait(contextTrait)) {
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
        final OffsetMatch match;
        int score;
        final List<String> scoreReasons;
        final List<String> validations;

        RecoveryResult(String offsetName, String staticLabel, String sourceLabel, StringHit anchor,
                Address stringReferenceAddress, Function xrefFunction, Function sourceFunction, int callDepth,
                OffsetMatch match, int score, List<String> scoreReasons, List<String> validations) {
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
            this.scoreReasons = scoreReasons;
            this.validations = validations;
        }

    }

    private static class UniquePattern {
        final String pattern;
        final int matchCount;
        final Address start;
        final int bytesToSkip;
        final int byteLength;
        final int fixedByteCount;

        UniquePattern(String pattern, int matchCount, Address start, int bytesToSkip, int byteLength,
                int fixedByteCount) {
            this.pattern = pattern;
            this.matchCount = matchCount;
            this.start = start;
            this.bytesToSkip = bytesToSkip;
            this.byteLength = byteLength;
            this.fixedByteCount = fixedByteCount;
        }

        boolean isBetterThan(UniquePattern other) {
            if (matchCount != other.matchCount) {
                return matchCount < other.matchCount;
            }
            if (byteLength != other.byteLength) {
                return byteLength < other.byteLength;
            }
            return fixedByteCount > other.fixedByteCount;
        }
    }

    private static class PatternBytes {
        final byte[] bytes;
        final boolean[] mask;
        final int firstMaskedIndex;
        final int fixedByteCount;

        PatternBytes(byte[] bytes, boolean[] mask) {
            this.bytes = bytes;
            this.mask = mask;
            int first = -1;
            int fixed = 0;
            for (int i = 0; i < mask.length; i++) {
                if (mask[i]) {
                    fixed++;
                    if (first < 0) {
                        first = i;
                    }
                }
            }
            this.firstMaskedIndex = first;
            this.fixedByteCount = fixed;
        }
    }

    private static class OffsetMatch {
        Address matchAddress;
        final Address instructionAddress;
        final Address resolvedAddress;
        String outputPattern;
        int bytesToSkip;
        final String matchKind;
        int patternMatchCount;
        final Set<String> traits;

        OffsetMatch(Address matchAddress, Address instructionAddress, Address resolvedAddress,
                String outputPattern, int bytesToSkip, String matchKind, int patternMatchCount, String... traits) {
            this.matchAddress = matchAddress;
            this.instructionAddress = instructionAddress;
            this.resolvedAddress = resolvedAddress;
            this.outputPattern = outputPattern;
            this.bytesToSkip = bytesToSkip;
            this.matchKind = matchKind;
            this.patternMatchCount = patternMatchCount;
            this.traits = new HashSet<>();
            for (String trait : traits) {
                if (trait != null && trait.length() > 0) {
                    this.traits.add(trait);
                }
            }
        }

        boolean hasTrait(String trait) {
            return traits.contains(trait);
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
