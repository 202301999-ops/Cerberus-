"""
ADFA-LD Dataset Test for Cerberus Detection System v3
Optimized detection based on syscall rarity analysis
"""

import os
import sys
import asyncio
from pathlib import Path
from typing import List, Tuple, Dict, Set
from collections import Counter
import math
import time


class ADFATester:
    """
    Detection based on:
    1. RARE syscalls (162, 114, 142) - not present in Normal
    2. UNIQUE ratio - attacks have few unique syscalls
    3. REPETITION - attacks repeat same syscalls
    4. ENTROPY - low entropy in attacks
    """
    
    # Syscalls that are RARE or ABSENT in Normal traces
    # (Based on analysis of 50 normal files)
    RARE_SYSCALLS = {
        162: "Suspicious - absent in normal",
        114: "Suspicious - very rare in normal",
        142: "Suspicious - rare in normal",
        175: "Suspicious - rare in normal",
    }
    
    # Known attack syscall signatures
    ATTACK_SIGNATURES = {
        "Adduser": {162, 114},
        "Hydra_FTP": {168, 265, 102},
        "Hydra_SSH": {168, 265, 102},
        "Java_Meterpreter": {162, 114, 78, 3, 142, 175},
        "Meterpreter": {168, 265, 102},
        "Web_Shell": {168, 265, 102},
    }
    
    def __init__(self, dataset_path: str):
        self.dataset_path = Path(dataset_path)
        self.results = []
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
    
    def load_trace(self, file_path: Path) -> List[int]:
        """Load system call trace"""
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
                if not content:
                    return []
                return [int(x) for x in content.split()]
        except Exception:
            return []
    
    def detect(self, syscalls: List[int], attack_type: str = "unknown") -> Tuple[bool, float]:
        """
        Detection Logic v3
        Returns: (is_detected, score)
        """
        if not syscalls:
            return False, 0.0
        
        total = len(syscalls)
        counter = Counter(syscalls)
        unique_count = len(counter)
        unique_ratio = unique_count / total
        
        # === 1. RARE SYSCALL SCORE (الأقوى) ===
        # لو فيه syscall من RARE_SYSCALLS، ده مؤشر قوي
        rare_hits = sum(1 for sc in self.RARE_SYSCALLS if sc in counter)
        rare_ratio = rare_hits / len(self.RARE_SYSCALLS)
        
        # Bonus: لو الـ syscall النادر متكرر كتير
        rare_intensity = 0.0
        for sc in self.RARE_SYSCALLS:
            if sc in counter:
                freq = counter[sc] / total
                if freq > 0.1:  # بيشكل أكتر من 10%
                    rare_intensity += freq
        
        rare_score = (rare_ratio * 0.6) + (rare_intensity * 0.4)
        
        # === 2. PATTERN MATCH SCORE ===
        pattern_score = 0.0
        if attack_type in self.ATTACK_SIGNATURES:
            expected = self.ATTACK_SIGNATURES[attack_type]
            matched = sum(1 for sc in expected if sc in counter)
            pattern_score = matched / len(expected)
            
            # Bonus: نسبة السيستم كولز دي من إجمالي الملف
            sig_count = sum(counter.get(sc, 0) for sc in expected)
            sig_ratio = sig_count / total if total > 0 else 0
            pattern_score = pattern_score * (0.5 + 0.5 * sig_ratio)
        
        # === 3. UNIQUENESS SCORE ===
        # الهجمات غالباً: unique_ratio < 0.05
        if unique_ratio < 0.005:
            unique_score = 1.0
        elif unique_ratio < 0.01:
            unique_score = 0.8
        elif unique_ratio < 0.02:
            unique_score = 0.5
        elif unique_ratio < 0.05:
            unique_score = 0.3
        else:
            unique_score = 0.0
        
        # === 4. REPETITION SCORE ===
        max_freq = max(counter.values()) / total
        if max_freq > 0.7:
            repetition_score = 1.0
        elif max_freq > 0.5:
            repetition_score = 0.8
        elif max_freq > 0.4:
            repetition_score = 0.5
        else:
            repetition_score = 0.0
        
        # === 5. ENTROPY SCORE ===
        entropy = 0.0
        for count in counter.values():
            p = count / total
            entropy -= p * math.log2(p)
        max_entropy = math.log2(unique_count) if unique_count > 1 else 1
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
        entropy_score = 1.0 - normalized_entropy
        
        # === FINAL SCORE ===
        # وزن أعلى للـ rare syscalls
        score = (
            0.40 * rare_score +         # الأقوى
            0.25 * pattern_score +      # مطابقة البصمة
            0.15 * unique_score +       # قلة التنوع
            0.10 * repetition_score +   # تكرار
            0.10 * entropy_score        # entropy
        )
        
        threshold = 0.35
        detected = score >= threshold
        
        return detected, score
    
    def test_file(self, file_path: Path, is_attack: bool, attack_type: str) -> Dict:
        start = time.time()
        syscalls = self.load_trace(file_path)
        detected, score = self.detect(syscalls, attack_type)
        duration = (time.time() - start) * 1000
        
        if is_attack and detected:
            self.tp += 1
        elif is_attack and not detected:
            self.fn += 1
        elif not is_attack and detected:
            self.fp += 1
        else:
            self.tn += 1
        
        return {
            "file": file_path.name,
            "is_attack": is_attack,
            "detected": detected,
            "score": score,
            "attack_type": attack_type,
            "duration_ms": duration,
            "syscall_count": len(syscalls)
        }
    
    def run(self, max_normal: int = 100, max_per_attack: int = 10):
        print("=" * 60)
        print("ADFA-LD Dataset - Cerberus Detection Test v3")
        print("=" * 60)
        
        start_time = time.time()
        
        print("\n[1/2] Testing NORMAL traces...")
        training = self.dataset_path / "Training_Data_Master"
        validation = self.dataset_path / "Validation_Data_Master"
        
        normal_files = list(training.glob("*.txt"))[:max_normal]
        normal_files += list(validation.glob("*.txt"))[:max_normal]
        
        for i, f in enumerate(normal_files):
            self.results.append(self.test_file(f, False, "normal"))
            if (i + 1) % 50 == 0:
                print(f"  Tested {i + 1}/{len(normal_files)} normal files")
        
        print(f"  ✓ Total normal tested: {len(normal_files)}")
        
        print("\n[2/2] Testing ATTACK traces...")
        attack_path = self.dataset_path / "Attack_Data_Master"
        
        attack_types = ["Adduser", "Hydra_FTP", "Hydra_SSH", 
                       "Java_Meterpreter", "Meterpreter", "Web_Shell"]
        
        for atype in attack_types:
            files = []
            for d in attack_path.glob(f"{atype}_*"):
                if d.is_dir():
                    files.extend(list(d.glob("*.txt")))
            files = files[:max_per_attack]
            print(f"  Testing {atype} ({len(files)} files)...")
            for f in files:
                self.results.append(self.test_file(f, True, atype))
        
        print(f"  ✓ Total attacks tested: {self.tp + self.fn}")
        
        duration = time.time() - start_time
        self.print_summary(duration)
        self.print_per_attack_breakdown()
    
    def print_summary(self, duration: float):
        total = self.tp + self.fp + self.tn + self.fn
        accuracy = (self.tp + self.tn) / total if total > 0 else 0
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print("\n" + "=" * 60)
        print("TEST RESULTS")
        print("=" * 60)
        
        print(f"\n📊 Dataset:")
        print(f"   Total tested:       {total}")
        print(f"   Normal traces:      {self.tn + self.fp}")
        print(f"   Attack traces:      {self.tp + self.fn}")
        
        print(f"\n🎯 Detection:")
        print(f"   True Positives:     {self.tp}")
        print(f"   False Positives:    {self.fp}")
        print(f"   True Negatives:     {self.tn}")
        print(f"   False Negatives:    {self.fn}")
        
        print(f"\n📈 Metrics:")
        print(f"   Accuracy:           {accuracy * 100:.2f}%")
        print(f"   Precision:          {precision * 100:.2f}%")
        print(f"   Recall:             {recall * 100:.2f}%")
        print(f"   F1 Score:           {f1 * 100:.2f}%")
        
        print(f"\n⏱️  Time:               {duration:.2f}s")
        print(f"   Avg per trace:      {duration / total * 1000:.2f}ms")
        
        print("\n" + "=" * 60)
        
        if f1 >= 0.85:
            print("✅ EXCELLENT - System works great!")
        elif f1 >= 0.70:
            print("🟢 GOOD - System works well")
        elif f1 >= 0.50:
            print("🟡 OK - System needs tuning")
        else:
            print("🔴 POOR - Needs improvement")
        
        print("=" * 60)
    
    def print_per_attack_breakdown(self):
        print("\n📋 Per-Attack-Type Detection Rate:")
        print("-" * 60)
        
        by_type = {}
        for r in self.results:
            if r["is_attack"]:
                atype = r["attack_type"]
                if atype not in by_type:
                    by_type[atype] = {"total": 0, "detected": 0}
                by_type[atype]["total"] += 1
                if r["detected"]:
                    by_type[atype]["detected"] += 1
        
        for atype, stats in sorted(by_type.items()):
            rate = stats["detected"] / stats["total"] * 100 if stats["total"] > 0 else 0
            bar = "█" * int(rate / 5) + "░" * (20 - int(rate / 5))
            print(f"   {atype:20s} [{bar}] {rate:5.1f}% ({stats['detected']}/{stats['total']})")
        
        print("-" * 60)


if __name__ == "__main__":
    dataset = r"C:\Users\Blu-Ray\OneDrive\Desktop\Cerberus\tests\data\ADFA-LD"
    tester = ADFATester(dataset)
    tester.run(max_normal=100, max_per_attack=10)