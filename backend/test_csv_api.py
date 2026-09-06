import asyncio
import io
import sys
from pathlib import Path
from fastapi import UploadFile, HTTPException

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from app.database import get_db, init_db
from app.routes.prediction import upload_traffic_csv, load_sample_dataset
from app.main import health_check

async def run_async_tests():
    init_db()
    db = next(get_db())

    # 1. Test Health
    h = await health_check()
    assert h['status'] == 'HEALTHY'
    print('1. Health check PASSED:', h['status'])

    # 2. Test Load Sample
    res_sample = await load_sample_dataset(db=db)
    assert res_sample.records_processed == 90
    print('2. Load sample PASSED:', res_sample.records_processed, 'records')

    # 3. Test Valid CSV Upload
    sample_file = BASE_DIR / 'data' / 'sample_cicids2018_test.csv'
    with open(sample_file, 'rb') as f:
        content = f.read()
    
    upload_file = UploadFile(filename='sample.csv', file=io.BytesIO(content))
    res_upload = await upload_traffic_csv(file=upload_file, db=db)
    assert res_upload.records_processed == 90
    print('3. Valid CSV upload PASSED:', res_upload.records_processed, 'records')

    # 4. Test Empty CSV Upload
    empty_file = UploadFile(filename='empty.csv', file=io.BytesIO(b''))
    try:
        await upload_traffic_csv(file=empty_file, db=db)
        raise AssertionError("Should have raised 400 for empty CSV")
    except HTTPException as e:
        assert e.status_code == 400
        print('4. Empty CSV validation PASSED: 400 returned:', e.detail)

    # 5. Test Invalid Extension Upload
    txt_file = UploadFile(filename='invalid.txt', file=io.BytesIO(b'hello'))
    try:
        await upload_traffic_csv(file=txt_file, db=db)
        raise AssertionError("Should have raised 400 for invalid extension")
    except HTTPException as e:
        assert e.status_code == 400
        print('5. Invalid extension validation PASSED: 400 returned:', e.detail)

    print('ALL BACKEND INTEGRATION TESTS PASSED!')

if __name__ == '__main__':
    asyncio.run(run_async_tests())
