"""Opening the website cap keeps accounting and provider failures intact."""
from concurrent.futures import ThreadPoolExecutor
import os
import unittest
from unittest.mock import patch
from sqlalchemy import select,func,update
from sqlalchemy.exc import IntegrityError
import cloud_budget
from cloud_vision import CloudVisionError
import test_scan_v2


class CloudOpenUsageTests(unittest.TestCase):
    setUp=test_scan_v2.PaidScanAPITests.setUp
    tearDown=test_scan_v2.PaidScanAPITests.tearDown
    photo=test_scan_v2.PaidScanAPITests.photo
    upload=test_scan_v2.PaidScanAPITests.upload
    wait=test_scan_v2.PaidScanAPITests.wait

    def used(self):
        with self.engine.connect() as c:
            return c.scalar(select(cloud_budget.counter.c.calls).where(cloud_budget.counter.c.id==cloud_budget.KEY))

    def test_only_explicit_minus_one_opens_usage(self):
        for value,expected in [('-1',-1),(-2,0),(0,0),(20,20),(1001,1000)]:
            self.assertEqual(cloud_budget.configured_limit(value),expected)
        with self.assertRaises(ValueError):cloud_budget.configured_limit('unlimited-typo')

    def test_open_mode_defaults_cloud_without_consuming_usage(self):
        self.app.config['CLOUD_TRIAL_LIMIT']=-1
        with self.engine.begin() as c:c.execute(update(cloud_budget.counter).values(calls=1001))
        for _ in range(3):
            config=self.client.get('/api/scan-config').json['recognition']
            self.assertTrue(config['cloud_unlimited']);self.assertTrue(config['cloud_available'])
            self.assertEqual(config['default_engine'],'cloud')
            self.assertIsNone(config['cloud_limit']);self.assertIsNone(config['cloud_remaining'])
        self.assertEqual(self.used(),1001);self.assertEqual(self.cloud.calls,0)

    def test_open_mode_without_key_stays_unavailable(self):
        self.app.config.update(CLOUD_TRIAL_LIMIT=-1,CLOUD_OCR=None)
        with patch.dict(os.environ,{'OPENAI_API_KEY':'   '}):
            config=self.client.get('/api/scan-config').json['recognition']
            self.assertFalse(config['cloud_available']);self.assertEqual(config['default_engine'],'local')
            self.assertEqual(self.upload().status_code,409)
        self.assertEqual(self.used(),0)

    def test_open_upload_after_twenty_still_records_tokens_and_replay_once(self):
        with self.engine.begin() as c:c.execute(update(cloud_budget.counter).values(calls=20))
        self.app.config['CLOUD_TRIAL_LIMIT']=-1
        submitted=self.upload();self.assertEqual(submitted.status_code,202,submitted.json)
        self.assertEqual(self.wait(submitted.json['id'])['state'],'done')
        replay=self.upload();self.assertEqual(replay.json['id'],submitted.json['id'])
        self.assertEqual(self.cloud.calls,1);self.assertEqual(self.used(),21)
        with self.engine.connect() as c:
            row=c.execute(select(cloud_budget.calls).where(cloud_budget.calls.c.job_id==submitted.json['id'])).mappings().one()
        self.assertEqual(row['state'],'done');self.assertEqual(row['usage']['total_tokens'],40)

    def test_open_reservations_remain_atomic_and_duplicate_safe(self):
        def reserve(i):cloud_budget.reserve(self.engine,f'{i:032x}','offline',-1)
        with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(reserve,range(32)))
        self.assertEqual(self.used(),32)
        with self.assertRaises(IntegrityError):reserve(0)
        self.assertEqual(self.used(),32)
        with self.engine.connect() as c:self.assertEqual(c.scalar(select(func.count()).select_from(cloud_budget.calls)),32)
        self.assertIsNone(cloud_budget.remaining(self.engine,-1))

    def test_provider_quota_failure_is_retained_without_retry_or_local_fallback(self):
        self.app.config['CLOUD_TRIAL_LIMIT']=-1
        self.cloud.error=CloudVisionError('quota',request_may_be_billed=True)
        submitted=self.upload();self.assertEqual(submitted.status_code,202,submitted.json)
        failed=self.wait(submitted.json['id']);self.assertEqual(failed['state'],'failed')
        self.assertEqual(self.cloud.calls,1);self.assertEqual(self.local.calls,0);self.assertEqual(self.used(),1)
        with self.engine.connect() as c:
            row=c.execute(select(cloud_budget.calls).where(cloud_budget.calls.c.job_id==submitted.json['id'])).mappings().one()
        self.assertEqual((row['state'],row['error_code']),('failed','quota'))

    def test_switching_back_to_finite_or_disabled_does_not_reset_history(self):
        cloud_budget.reserve(self.engine,'a'*32,'offline',-1)
        self.app.config['CLOUD_TRIAL_LIMIT']=1
        config=self.client.get('/api/scan-config').json['recognition']
        self.assertFalse(config['cloud_available']);self.assertFalse(config['cloud_unlimited'])
        self.assertEqual(config['cloud_remaining'],0)
        self.assertEqual(self.upload(request_id='b'*32).status_code,429)
        self.app.config['CLOUD_TRIAL_LIMIT']=0
        self.assertEqual(self.upload(request_id='c'*32).status_code,429)
        self.assertEqual(self.used(),1)


if __name__=='__main__':unittest.main()
