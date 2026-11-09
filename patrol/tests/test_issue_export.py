"""Isolated workbook verification: snapshots, embedded photos, links and bounds."""
from datetime import datetime, timezone, timedelta
from io import BytesIO
from zipfile import ZipFile
from xml.etree import ElementTree as ET

import pytest
from openpyxl import load_workbook
from PIL import Image

import issue_export as exporter
from issue_export import (ExportEvent, ExportImageError, ExportIssue, ExportLimitError,
                          ExportPhoto, build_issue_workbook)


NOW = datetime(2026, 11, 9, 2, 30, tzinfo=timezone.utc)


def photo(color='red', size=(900, 600), label=''):
    data = BytesIO()
    image = Image.new('RGB', size, color)
    image.save(data, 'PNG')
    image.close()
    return ExportPhoto(data.getvalue(), label)


def case(**changes):
    values = dict(inspection_id=17, point_code='1F-T001', point_name='測試設備', floor='1F',
        responsible_team='工務', reporter='測試巡檢員', reported_at=NOW,
        status='open', note='設備有異常\n請確認安全後再處理。')
    values.update(changes)
    return ExportIssue(**values)


def read(rows, **options):
    with build_issue_workbook(rows, generated_at=NOW, **options) as stream:
        assert stream.tell() == 0
        data = stream.read()
    return load_workbook(BytesIO(data)), data


def all_text(ws):
    return '\n'.join(str(c.value) for row in ws for c in row if c.value is not None)


def test_empty_export_has_valid_headers_and_no_private_or_external_content():
    workbook, data = read([])
    assert workbook.sheetnames == ['異常總表', '照片與處理歷程']
    sheet = workbook['異常總表']
    assert tuple(c.value for c in sheet[5]) == exporter.OVERVIEW_HEADERS
    assert sheet['G2'].value == datetime(2026, 11, 9, 10, 30)
    assert sheet.freeze_panes == 'E6'
    assert sheet.auto_filter.ref == 'A5:O5'
    assert '沒有異常案件' in sheet['A6'].value
    with ZipFile(BytesIO(data)) as archive:
        assert not any(name.startswith(('xl/media/', 'xl/externalLinks/')) for name in archive.namelist())


def test_case_order_taipei_dates_internal_links_and_filters_are_preserved():
    first = case(inspection_id=200, point_code='0007', reported_at=NOW.replace(tzinfo=None))
    second = case(inspection_id=3, point_code='X/[]:*?\\' + '長' * 50,
                  reported_at=NOW.astimezone(timezone(timedelta(hours=7))))
    workbook, data = read([first, second], filter_description='工務　2026/11/01–11/09')
    overview, detail = workbook.worksheets
    assert (overview['A6'].value, overview['A7'].value) == (200, 3)
    assert overview['D6'].value == '0007' and overview['D6'].data_type == 's'
    assert overview['G6'].value == overview['G7'].value == datetime(2026, 11, 9, 10, 30)
    assert overview['A3'].value == '工務　2026/11/01–11/09'
    assert overview['O6'].hyperlink.location == "'照片與處理歷程'!A1"
    for address in ('O6', 'O7'):
        target = overview[address].hyperlink
        assert not target.target and detail[target.location.split('!')[1]].value.startswith('異常案件 #')
    assert detail['A2'].hyperlink.location == "'異常總表'!A6"
    assert len(detail.row_breaks.brk) == 1
    assert all(len(name) <= 31 for name in workbook.sheetnames)
    with ZipFile(BytesIO(data)) as archive:
        assert all(b'TargetMode="External"' not in archive.read(name)
                   for name in archive.namelist() if name.endswith('.rels'))


@pytest.mark.parametrize('payload', ['=1+1', '+SUM(A1:A2)', '-1+2', '@SUM(A1:A2)', '#REF!', '＝1+1'])
def test_untrusted_text_stays_literal_not_formula(payload):
    item = case(point_code=payload, point_name=payload, reporter=payload, note=payload,
        events=(ExportEvent('resolved', payload, NOW, payload),), status='resolved')
    workbook, data = read([item])
    for ws in workbook:
        for row in ws:
            assert all(c.data_type != 'f' for c in row)
    for col in ('D', 'E', 'F', 'I', 'J', 'L'):
        cell = workbook['異常總表'][col + '6']
        assert cell.value == payload and cell.data_type == 's'
    with ZipFile(BytesIO(data)) as archive:
        for name in archive.namelist():
            if name.startswith('xl/worksheets/sheet') and name.endswith('.xml'):
                xml = ET.fromstring(archive.read(name))
                assert xml.findall('.//{http://schemas.openxmlformats.org/spreadsheetml/2006/main}f') == []


def test_reopen_cycles_keep_all_photos_and_latest_resolution_comparison():
    original = photo('red', (1200, 800), '原始異常照片')
    earlier = ExportEvent('resolved', '處理人員甲', NOW + timedelta(hours=1), '第一次改善',
                         (photo('blue', (600, 900), '前次結案照片'),))
    reopened = ExportEvent('reopened', '管理人員', NOW + timedelta(hours=2), '再次發現問題',
                          (photo('yellow', (300, 300), '重開附件'),))
    latest = ExportEvent('resolved', '處理人員乙', NOW + timedelta(hours=3), '第二次改善已完成',
                        (photo('green', (900, 300), '最新改善照片'),))
    last_reopen = ExportEvent('reopened', '管理人員', NOW + timedelta(hours=4), '重新檢查')
    workbook, data = read([case(photos=(original,), events=(latest, earlier, last_reopen, reopened))])
    overview, detail = workbook.worksheets
    assert overview['H6'].value == '未結案'
    assert overview['J6'].value == '處理人員乙'
    assert overview['K6'].value == datetime(2026, 11, 9, 13, 30)
    assert (overview['M6'].value, overview['N6'].value) == (1, 3)
    content = all_text(detail)
    for label in ('原始異常照片', '前次結案照片', '重開附件', '最新改善照片',
                  '第一次改善', '再次發現問題', '第二次改善已完成', '重新檢查', '目前已重新開啟'):
        assert label in content
    # Latest resolution photos are embedded once and linked from its history.
    assert len(detail._images) == 4
    assert sorted(image.anchor._from.col for image in detail._images) == [0, 0, 0, 7]
    assert len([c for row in detail for c in row if c.hyperlink]) == 2
    with ZipFile(BytesIO(data)) as archive:
        media = [name for name in archive.namelist() if name.startswith('xl/media/')]
        assert len(media) == 4
        for name in media:
            with Image.open(BytesIO(archive.read(name))) as embedded:
                assert embedded.format == 'JPEG'
                assert embedded.width <= 480 and embedded.height <= 360
                assert 'exif' not in embedded.info
                assert len(archive.read(name)) < 50000


def test_long_multiline_cjk_notes_are_complete_and_readable_in_detail():
    note = '繁體中文測試內容' * 200 + '\n第二段說明\n\n最後一行'
    workbook, _ = read([case(note=note)])
    overview, detail = workbook.worksheets
    assert overview['I6'].value == note
    start = next(c.row for row in detail for c in row if c.value == '改善前｜原始異常回報') + 1
    end = next(c.row for row in detail for c in row if c.value == '未附照片')
    lines = [detail.cell(row, 1).value or '' for row in range(start, end)]
    assert ''.join(lines).replace('\n', '') == note.replace('\n', '')
    assert end - start > 40
    assert all((detail.row_dimensions[row].height or 20) >= 20 for row in range(start, end))


def test_legacy_resolution_without_events_is_retained():
    workbook, _ = read([case(status='resolved', resolved_by='既有處理人員', resolved_at=NOW,
        resolution_note='既有結案說明')])
    assert workbook['異常總表']['J6'].value == '既有處理人員'
    assert workbook['異常總表']['L6'].value == '既有結案說明'
    assert '最近一次結案未附照片' in all_text(workbook['照片與處理歷程'])


@pytest.mark.parametrize('actor', ['處理人員' * 25, 'Nguyễn Thị ' * 9, 'Pelaksana kebersihan ' * 5])
def test_long_resolution_actor_names_expand_merged_history_row(actor):
    workbook, _ = read([case(events=(ExportEvent('resolved', actor, NOW, '處理完成'),), status='resolved')])
    detail = workbook['照片與處理歷程']
    heading = next(cell for row in detail for cell in row if cell.value == '1. 結案　' + actor)
    assert heading.alignment.wrap_text is True
    assert detail.row_dimensions[heading.row].height >= len(exporter._wrapped_lines(heading.value, 62)) * 20
    assert detail.row_dimensions[heading.row].height > 25
    assert detail.cell(heading.row + 1, 1).value == '處理完成'


def test_limits_fail_before_decoding_and_never_silently_truncate(monkeypatch):
    with pytest.raises(ExportLimitError, match='100'):
        build_issue_workbook(case(inspection_id=i) for i in range(1, 102))
    with pytest.raises(ExportLimitError, match='500'):
        build_issue_workbook([case(photos=(ExportPhoto(b'not decoded'),) * 501)])
    monkeypatch.setattr(exporter, 'MAX_SOURCE_PHOTO_BYTES', 10)
    with pytest.raises(ExportLimitError, match='50 MB'):
        build_issue_workbook([case(photos=(ExportPhoto(b'not decoded 123'),))])


def test_invalid_images_fail_with_actionable_error_and_no_incomplete_workbook():
    for invalid in (b'', b'https://example.invalid/private-photo.jpg', b'broken-image'):
        with pytest.raises(ExportImageError, match='照片'):
            build_issue_workbook([case(photos=(ExportPhoto(invalid),))])


def test_duplicate_ids_and_invalid_actions_do_not_create_ambiguous_report():
    with pytest.raises(ValueError, match='重複'):
        build_issue_workbook([case(), case()])
    with pytest.raises(ValueError, match='歷程'):
        build_issue_workbook([case(events=(ExportEvent('unknown', '測試人員', NOW),))])
