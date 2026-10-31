from pathlib import Path
from forensic.pipeline import load_logs, make_features, analyze, explain_record

DATA = Path(__file__).resolve().parents[1] / 'data' / 'demo_bgl.csv'

def test_end_to_end():
    logs = load_logs(DATA.read_bytes(), DATA.name)
    assert len(logs) >= 10
    assert set(['label','component','message']).issubset(logs.columns)
    features = make_features(logs)
    assert features.shape == (len(logs), 5)
    result = analyze(logs)
    assert len(result.logs) == len(logs)
    assert result.logs['prediction'].isin([-1, 1]).all()
    assert len(explain_record(result, 0)) == 5

def test_raw():
    raw = b'- 111 2005.06.03 NODE 2005-06-03-12.00.00 NODE KERNEL INFO Normal system message\n'
    logs = load_logs(raw, 'BGL.log')
    assert len(logs) == 1
    assert 'Normal' in logs.iloc[0]['message']
