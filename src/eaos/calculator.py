"""Pure bounded calculator. Executed in a time-limited child process by the tool."""
import ast
import json
import sys

NAMES = {k: v for k, v in dict(int=int, str=str, bytes=bytes, len=len, hex=hex,
    bin=bin, abs=abs, min=min, max=max, round=round, sum=sum, list=list, tuple=tuple,
    chr=chr, ord=ord, range=range, enumerate=enumerate, zip=zip, sorted=sorted,
    float=float).items()}
ATTRS = {'to_bytes','from_bytes','fromhex','hex','decode','encode','replace','split','join','strip'}
ALLOWED = (ast.Expression,ast.Constant,ast.List,ast.Tuple,ast.Dict,ast.Set,ast.Load,
    ast.Store,ast.BinOp,ast.UnaryOp,ast.BoolOp,ast.Compare,ast.IfExp,ast.Subscript,
    ast.Slice,ast.Call,ast.Name,ast.Attribute,ast.keyword,ast.Add,ast.Sub,ast.Mult,
    ast.Div,ast.FloorDiv,ast.Mod,ast.Pow,ast.BitAnd,ast.BitOr,ast.BitXor,ast.LShift,
    ast.RShift,ast.UAdd,ast.USub,ast.Invert,ast.And,ast.Or,ast.Not,ast.Eq,ast.NotEq,
    ast.Lt,ast.LtE,ast.Gt,ast.GtE,ast.In,ast.NotIn,ast.ListComp,ast.SetComp,
    ast.DictComp,ast.GeneratorExp,ast.comprehension,ast.Lambda,ast.arguments,ast.arg)


def calculate(expression):
    if len(expression) > 10000:
        raise ValueError("Expression too long")
    tree = ast.parse(expression, mode='eval')
    nodes = list(ast.walk(tree))
    if len(nodes) > 2000:
        raise ValueError("Expression too complex")
    bound = {n.arg for n in nodes if isinstance(n, ast.arg)} | {
        n.id for n in nodes if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    for node in nodes:
        if not isinstance(node, ALLOWED):
            raise ValueError("Unsupported expression")
        if isinstance(node, ast.Name) and node.id not in NAMES and node.id not in bound:
            raise ValueError("Unsupported name")
        if isinstance(node, ast.Attribute) and node.attr not in ATTRS:
            raise ValueError("Unsupported attribute")
    return repr(eval(compile(tree, '<calculator>', 'eval'), {'__builtins__': {}, **NAMES}, {}))


if __name__ == '__main__':
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
        # Darwin advertises RLIMIT_AS but rejects setting it (EINVAL). Keep the
        # CPU limit and caller's four-second timeout there; do not fail every sum.
        if sys.platform != 'darwin':
            resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024))
        print(calculate(json.load(sys.stdin)['expression']))
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
