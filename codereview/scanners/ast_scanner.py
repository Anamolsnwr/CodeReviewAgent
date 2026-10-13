"""AST-based Python static analyzer for syntax, security, and quality issues."""

import ast
from typing import List, Optional
from codereview.models import Finding, Severity, Category


class ASTScanner:
    """Performs abstract syntax tree checks on Python code."""

    def scan(
        self,
        filename: str,
        code: str,
        changed_lines: Optional[List[int]] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as syn_err:
            line_no = syn_err.lineno or 1
            is_new = changed_lines is None or (line_no in changed_lines)
            findings.append(Finding(
                file_path=filename,
                line_number=line_no,
                end_line_number=syn_err.end_lineno or line_no,
                rule_id="SYNTAX-ERROR",
                severity=Severity.CRITICAL,
                category=Category.BUG,
                message=f"Syntax Error: {syn_err.msg}",
                explanation=f"Code failed Python AST compilation: {syn_err.msg} at line {line_no}, col {syn_err.offset}.",
                suggestion="Fix the syntax error to ensure valid executable Python code.",
                confidence=1.0,
                code_snippet=(syn_err.text or "").strip(),
                newly_introduced=is_new,
            ))
            return findings

        # Walk AST
        lines = code.splitlines()

        for node in ast.walk(tree):
            line_no = getattr(node, "lineno", 1)
            is_new = changed_lines is None or (line_no in changed_lines)
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""

            # Check 1: eval() / exec()
            if isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in ("eval", "exec"):
                    findings.append(Finding(
                        file_path=filename,
                        line_number=line_no,
                        rule_id=f"SEC-AST-{func_name.upper()}",
                        severity=Severity.CRITICAL,
                        category=Category.SECURITY,
                        message=f"Dangerous call to {func_name}()",
                        explanation=f"{func_name}() evaluates arbitrary code strings and can allow Remote Code Execution.",
                        suggestion="Replace with safe parsers like ast.literal_eval() or explicit data structures.",
                        confidence=1.0,
                        code_snippet=snippet,
                        newly_introduced=is_new,
                    ))

                # Check subprocess shell=True
                if func_name in ("Popen", "run", "call", "check_output", "check_call"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(Finding(
                                file_path=filename,
                                line_number=line_no,
                                rule_id="SEC-AST-SHELL-TRUE",
                                severity=Severity.HIGH,
                                category=Category.SECURITY,
                                message="Subprocess invoked with shell=True",
                                explanation="Invoking subprocess with shell=True exposes the application to command injection.",
                                suggestion="Set shell=False and pass arguments as a list of strings.",
                                confidence=1.0,
                                code_snippet=snippet,
                                newly_introduced=is_new,
                            ))

            # Check 2: Bare except
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    findings.append(Finding(
                        file_path=filename,
                        line_number=line_no,
                        rule_id="QUAL-AST-BARE-EXCEPT",
                        severity=Severity.LOW,
                        category=Category.CODE_QUALITY,
                        message="Bare except clause catches all exceptions indiscriminately",
                        explanation="Bare except catches system interrupts (KeyboardInterrupt, SystemExit) and hides critical failures.",
                        suggestion="Catch specific exceptions, e.g. 'except Exception:' or 'except (ValueError, KeyError):'.",
                        confidence=1.0,
                        code_snippet=snippet,
                        newly_introduced=is_new,
                    ))

            # Check 3: Mutable default argument
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        findings.append(Finding(
                            file_path=filename,
                            line_number=line_no,
                            rule_id="BUG-AST-MUTABLE-DEFAULT",
                            severity=Severity.MEDIUM,
                            category=Category.BUG,
                            message=f"Mutable default argument in function '{node.name}'",
                            explanation="Default argument values are evaluated once at function definition, mutating across all subsequent calls.",
                            suggestion="Use None as default value and assign an empty collection inside the function.",
                            confidence=0.95,
                            code_snippet=snippet,
                            newly_introduced=is_new,
                        ))

            # Check 4: Insecure pickle import
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("pickle", "shelve", "marshal"):
                        findings.append(Finding(
                            file_path=filename,
                            line_number=line_no,
                            rule_id="SEC-AST-UNSAFE-DESERIALIZATION",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            message=f"Import of potentially unsafe serialization module '{alias.name}'",
                            explanation=f"Deserializing untrusted data with {alias.name} can result in arbitrary code execution.",
                            suggestion="Use safer serialization formats like JSON, MessagePack, or cryptography-backed tokens.",
                            confidence=0.85,
                            code_snippet=snippet,
                            newly_introduced=is_new,
                        ))

        return findings
