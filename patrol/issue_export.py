"""Pure-data, private XLSX issue reports with embedded before/after photos.

The caller authorizes and orders every case and supplies snapshot labels. This
module never queries the database, follows a URL, or reads a photo from disk.
Naive database datetimes mean UTC; workbook date cells are Taipei local time.
The returned seekable file belongs to the caller and must be closed after use.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from itertools import islice
from math import ceil
from tempfile import SpooledTemporaryFile
import unicodedata
import warnings
from zoneinfo import ZoneInfo

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.drawing.image import Image as SheetImage
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.hyperlink import Hyperlink
from openpyxl.worksheet.pagebreak import Break
from openpyxl.utils import get_column_letter
from PIL import Image, ImageOps, UnidentifiedImageError


MAX_EXPORT_ISSUES = 100
MAX_EXPORT_PHOTOS = 500
MAX_SOURCE_PHOTO_BYTES = 50 * 1024 * 1024
TAIPEI = ZoneInfo('Asia/Taipei')
DATE_FORMAT = 'yyyy/mm/dd hh:mm'
BODY = Font(name='Microsoft JhengHei', size=11, color='243544')
TITLE = Font(name='Microsoft JhengHei', size=16, bold=True, color='17324D')
HEADING = Font(name='Microsoft JhengHei', size=11, bold=True, color='FFFFFF')
LINK = Font(name='Microsoft JhengHei', size=11, color='216CA0', underline='single')
NAVY = PatternFill('solid', fgColor='264A68')
PALE = PatternFill('solid', fgColor='F2F6FA')
LINE = Border(bottom=Side(style='hair', color='DAE2E9'))
STATUS_LABELS = {'open': '未結案', 'resolved': '已結案'}
ACTION_LABELS = {'resolved': '結案', 'reopened': '重新開啟'}
OVERVIEW_HEADERS = ('案件編號', '負責單位', '樓層', '點位編號', '點位名稱', '回報人員',
                    '回報時間（台北）', '目前狀態', '異常說明', '最近結案人員',
                    '最近結案時間（台北）', '最近結案說明', '回報照片', '歷程照片', '案件明細')


class ExportLimitError(ValueError):
    """The caller must narrow the authorized export, never silently truncate it."""


class ExportImageError(ValueError):
    """A stored image could not be included; no partial workbook is returned."""


@dataclass(frozen=True)
class ExportPhoto:
    data: bytes
    label: str = ''


@dataclass(frozen=True)
class ExportEvent:
    action: str
    actor_name: str
    created_at: datetime | None
    note: str = ''
    photos: tuple[ExportPhoto, ...] = ()


@dataclass(frozen=True)
class ExportIssue:
    inspection_id: int
    point_code: str
    point_name: str
    floor: str
    responsible_team: str
    reporter: str
    reported_at: datetime | None
    status: str
    note: str = ''
    photos: tuple[ExportPhoto, ...] = ()
    events: tuple[ExportEvent, ...] = ()
    resolved_by: str = ''
    resolved_at: datetime | None = None
    resolution_note: str = ''
    checklist: str = ''
    execution_checklist: str = ''


def _utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _local(value):
    return _utc(value).astimezone(TAIPEI).replace(tzinfo=None) if value is not None else None


def _text(value):
    value = '' if value is None else str(value)
    if len(value) > 32767 or ILLEGAL_CHARACTERS_RE.search(value):
        raise ExportLimitError('部分文字超過 Excel 可儲存的長度或含不支援字元，請先修正內容再匯出。')
    return value


def _put(ws, row, col, value, *, header=False):
    cell = ws.cell(row, col)
    if isinstance(value, datetime):
        cell.value = _local(value)
        cell.number_format = DATE_FORMAT
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        cell.value = value
        cell.number_format = '#,##0'
    else:
        # Never let '=' (or an error-shaped value) become a formula or error.
        # Preserve the exact note rather than prefixing an apostrophe.
        cell.value = _text(value)
        cell.data_type = 's'
    cell.font = HEADING if header else BODY
    cell.alignment = Alignment(vertical='top', wrap_text=True, horizontal='center' if header else 'left')
    if header:
        cell.fill = NAVY
    return cell


def _merged(ws, row, first, last, value, *, header=False):
    ws.merge_cells(start_row=row, start_column=first, end_row=row, end_column=last)
    cell = _put(ws, row, first, value, header=header)
    if header:
        for col in range(first, last + 1):
            ws.cell(row, col).fill = NAVY
    return cell


def _wrapped_lines(value, units):
    """Split visible lines at Unicode width without losing characters/newlines."""
    lines = []
    for paragraph in _text(value).replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        line, width = '', 0
        for char in paragraph:
            size = 0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in ('F', 'W') else 1
            if line and width + size > units:
                lines.append(line)
                line, width = '', 0
            line, width = line + char, width + size
        lines.append(line)
    return lines or ['']


def _text_block(ws, row, first, last, value, units=52):
    for line in _wrapped_lines(value, units):
        _merged(ws, row, first, last, line)
        ws.row_dimensions[row].height = max(ws.row_dimensions[row].height or 0, 20)
        row += 1
    return row


def _link(cell, sheet, address='A1'):
    cell.hyperlink = Hyperlink(ref=cell.coordinate,
        location="'" + sheet.replace("'", "''") + "'!" + address, display=str(cell.value))
    cell.font = LINK


def _base_sheet(ws, *, landscape=False):
    ws.sheet_view.showGridLines = False
    ws.sheet_view.zoomScale = 100
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_setup.orientation = 'landscape' if landscape else 'portrait'
    ws.page_setup.paperSize = ws.PAPERSIZE_A4
    ws.page_setup.fitToWidth, ws.page_setup.fitToHeight = 1, 0
    ws.page_margins.left = ws.page_margins.right = 0.3
    ws.page_margins.top = ws.page_margins.bottom = 0.4
    ws.oddFooter.center.text = '第 &P 頁 / 共 &N 頁'
    ws.oddFooter.center.size = 9
    ws.sheet_properties.tabColor = '264A68'


def _ordered_events(issue):
    return sorted(enumerate(issue.events), key=lambda pair: (
        _utc(pair[1].created_at) if pair[1].created_at else datetime.min.replace(tzinfo=timezone.utc), pair[0]))


def _latest_resolution(issue, events):
    event = next((event for _, event in reversed(events) if event.action == 'resolved'), None)
    if event:
        return event.actor_name, event.created_at, event.note, event
    return issue.resolved_by, issue.resolved_at, issue.resolution_note, None


def _thumbnail(photo):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(BytesIO(photo.data)) as source:
                if source.width * source.height > 25_000_000 or getattr(source, 'n_frames', 1) != 1:
                    raise ExportImageError('附件圖片尺寸或格式不支援，請檢查異常案件的照片後再匯出。')
                source.load()
                oriented = ImageOps.exif_transpose(source)
                oriented.thumbnail((480, 360), Image.Resampling.LANCZOS)
                image = Image.new('RGB', oriented.size, 'white')
                if oriented.mode in ('RGBA', 'LA') or (oriented.mode == 'P' and 'transparency' in oriented.info):
                    rgba = oriented.convert('RGBA')
                    image.paste(rgba, mask=rgba.getchannel('A'))
                else:
                    image.paste(oriented.convert('RGB'))
                result = BytesIO()
                image.save(result, format='JPEG', quality=84, optimize=True)
                image.close()
                result.seek(0)
                return result
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError, Image.DecompressionBombWarning) as error:
        if isinstance(error, ExportImageError):
            raise
        raise ExportImageError('有附件照片無法讀取，請先檢查案件照片；本次沒有產生不完整的匯出檔。') from error


def _photo_column(ws, row, first, last, photos, streams, *, empty='未附照片'):
    if not photos:
        _merged(ws, row, first, last, empty)
        ws.row_dimensions[row].height = max(ws.row_dimensions[row].height or 0, 22)
        return row + 1
    for number, photo in enumerate(photos, 1):
        row = _text_block(ws, row, first, last, photo.label or f'照片 {number}')
        data = _thumbnail(photo)
        streams.append(data)  # openpyxl reads image data during save, not add_image.
        image = SheetImage(data)
        ratio = min(360 / image.width, 270 / image.height, 1)
        image.width, image.height = image.width * ratio, image.height * ratio
        ws.add_image(image, f'{get_column_letter(first)}{row}')
        height_rows = max(1, ceil(image.height * 0.75 / 20))
        for image_row in range(row, row + height_rows):
            ws.row_dimensions[image_row].height = max(ws.row_dimensions[image_row].height or 0, 20)
        row += height_rows + 1
    return row


def _detail(ws, issue, index, events, resolution, streams, start_row):
    if start_row > 1:
        ws.row_breaks.append(Break(id=start_row - 1))
    _merged(ws, start_row, 1, 13, f'異常案件 #{issue.inspection_id}').font = TITLE
    ws.row_dimensions[start_row].height = 32
    _link(_merged(ws, start_row + 1, 1, 6, '返回異常總表'), '異常總表', f'A{index + 5}')
    _merged(ws, start_row + 1, 8, 13, '目前狀態：' + STATUS_LABELS[issue.status])
    ws.row_dimensions[start_row + 1].height = 26
    row = _text_block(ws, start_row + 2, 1, 13, f'{issue.responsible_team}　{issue.floor}　{issue.point_code}　{issue.point_name}', 110)
    row = _text_block(ws, row, 1, 13, f'回報人員：{issue.reporter}', 110)
    _merged(ws, row, 1, 3, '回報時間（台北）')
    _merged(ws, row, 4, 8, issue.reported_at)
    ws.row_dimensions[row].height = 24
    row += 2
    if issue.checklist:
        row = _text_block(ws, row, 1, 13, '巡檢點檢項目\n' + issue.checklist, 110)
    if issue.execution_checklist:
        row = _text_block(ws, row, 1, 13, '對應執行點檢項目\n' + issue.execution_checklist, 110)
    actor, resolved_at, note, latest = resolution
    _merged(ws, row, 1, 6, '改善前｜原始異常回報', header=True)
    _merged(ws, row, 8, 13, '改善後｜最近一次結案', header=True)
    ws.row_dimensions[row].height = 27
    row += 1
    if issue.status == 'open' and latest is not None:
        message = '目前已重新開啟；右側為前次結案，案件尚未完成。'
    elif latest is None and not resolved_at:
        message = '尚無結案紀錄。'
    else:
        message = '最近結案人員：' + (actor or '未記錄')
    after_end = _text_block(ws, row, 8, 13, message)
    if issue.status == 'open' and latest is not None:
        after_end = _text_block(ws, after_end, 8, 13, '最近結案人員：' + (actor or '未記錄'))
    if resolved_at:
        _merged(ws, after_end, 8, 13, resolved_at)
        ws.row_dimensions[after_end].height = max(ws.row_dimensions[after_end].height or 0, 22)
        after_end += 1
    after_end = _text_block(ws, after_end, 8, 13, note or ('未填寫結案說明' if latest or resolved_at else ''))
    before_end = _text_block(ws, row, 1, 6, issue.note or '未填寫異常說明')
    photo_row = max(before_end, after_end) + 1
    before_end = _photo_column(ws, photo_row, 1, 6, issue.photos, streams)
    after_end = _photo_column(ws, photo_row, 8, 13, latest.photos if latest else (), streams,
                              empty='最近一次結案未附照片' if latest or resolved_at else '尚無改善後照片')
    row = max(before_end, after_end) + 1
    _merged(ws, row, 1, 13, '完整處理歷程', header=True)
    ws.row_dimensions[row].height = 27
    row += 1
    if not events:
        row = _text_block(ws, row, 1, 13, '尚無處理歷程。', 110)
    for sequence, (_, event) in enumerate(events, 1):
        row += 1
        event_heading = f'{sequence}. {ACTION_LABELS[event.action]}　{event.actor_name}'
        _merged(ws, row, 1, 8, event_heading)
        _merged(ws, row, 9, 13, event.created_at)
        for col in range(1, 14):
            ws.cell(row, col).fill = PALE
        # Excel does not auto-fit merged cells. Long Vietnamese/Indonesian
        # names and historical display names must not disappear under the note.
        ws.row_dimensions[row].height = max(25, len(_wrapped_lines(event_heading, 62)) * 20)
        row = _text_block(ws, row + 1, 1, 13, event.note, 110)
        if event is latest and event.photos:
            _link(_merged(ws, row, 1, 13, f'本次 {len(event.photos)} 張照片見上方「改善後」'), ws.title, f'H{photo_row}')
            ws.row_dimensions[row].height = 24
            row += 1
        elif event.photos:
            for start in range(0, len(event.photos), 2):
                left_end = _photo_column(ws, row, 1, 6, event.photos[start:start + 1], streams)
                right = event.photos[start + 1:start + 2]
                right_end = _photo_column(ws, row, 8, 13, right, streams) if right else row
                row = max(left_end, right_end)
    return row + 2


def _validate(rows):
    if len(rows) > MAX_EXPORT_ISSUES:
        raise ExportLimitError(f'一次最多匯出 {MAX_EXPORT_ISSUES} 件異常，請縮小日期或篩選範圍。')
    count, size = 0, 0
    seen = set()
    for issue in rows:
        if issue.inspection_id in seen or not isinstance(issue.inspection_id, int) or issue.inspection_id < 1:
            raise ValueError('匯出的案件編號不正確或重複。')
        seen.add(issue.inspection_id)
        if issue.status not in STATUS_LABELS or any(event.action not in ACTION_LABELS for event in issue.events):
            raise ValueError('匯出的異常狀態或處理歷程不正確。')
        for photos in (issue.photos, *(event.photos for event in issue.events)):
            for photo in photos:
                if not isinstance(photo.data, bytes) or not photo.data:
                    raise ExportImageError('有附件照片為空白或無法讀取，請先檢查案件照片後再匯出。')
                count, size = count + 1, size + len(photo.data)
                if count > MAX_EXPORT_PHOTOS or size > MAX_SOURCE_PHOTO_BYTES:
                    raise ExportLimitError('照片總量超過匯出上限（500 張或 50 MB），請縮小日期或篩選範圍。')


def build_issue_workbook(rows, *, generated_at=None, filter_description=''):
    """Return a rewound SpooledTemporaryFile containing a complete XLSX.

    ``rows`` contains authorized ExportIssue DTOs in caller-selected order.
    Photos are stored bytes, never paths/URLs. All supplied events/photos are
    retained, including old resolutions after reopening. Bounds reject the
    whole export before thumbnail generation; no records are silently omitted.
    """
    rows = list(islice(iter(rows), MAX_EXPORT_ISSUES + 1))
    _validate(rows)
    workbook, streams = Workbook(), []
    output = SpooledTemporaryFile(max_size=2 * 1024 * 1024, mode='w+b')
    try:
        workbook.properties.creator = '福和生鮮農產股份有限公司'
        workbook.properties.title = '巡檢異常追蹤'
        ws = workbook.active
        ws.title = '異常總表'
        _base_sheet(ws, landscape=True)
        _merged(ws, 1, 1, 15, '巡檢異常追蹤').font = TITLE
        ws.row_dimensions[1].height = 34
        _merged(ws, 2, 1, 4, f'共 {len(rows)} 件　未結案 {sum(r.status == "open" for r in rows)} 件')
        _merged(ws, 2, 5, 6, '匯出時間（台北）')
        _merged(ws, 2, 7, 9, generated_at or datetime.now(timezone.utc))
        ws.row_dimensions[2].height = 25
        _merged(ws, 3, 1, 15, filter_description or '依目前查詢條件匯出')
        ws.row_dimensions[3].height = 32
        _merged(ws, 4, 1, 15, '點「開啟明細」查看前後照片與完整歷程；「最近結案」可能是重新開啟前的處理紀錄。')
        ws.row_dimensions[4].height = 25
        widths = (12, 14, 10, 19, 28, 18, 23, 13, 42, 18, 23, 42, 12, 12, 16)
        for col, (header, width) in enumerate(zip(OVERVIEW_HEADERS, widths), 1):
            ws.column_dimensions[get_column_letter(col)].width = width
            _put(ws, 5, col, header, header=True)
        ws.row_dimensions[5].height = 34
        detail = workbook.create_sheet('照片與處理歷程')
        _base_sheet(detail)
        for col in range(1, 14):
            detail.column_dimensions[get_column_letter(col)].width = 9
        detail.column_dimensions['G'].width = 3
        detail_row = 1
        for index, issue in enumerate(rows, 1):
            events = _ordered_events(issue)
            resolution = _latest_resolution(issue, events)
            detail_anchor = detail_row
            detail_row = _detail(detail, issue, index, events, resolution, streams, detail_row)
            actor, resolved_at, note, _ = resolution
            values = (issue.inspection_id, issue.responsible_team, issue.floor, issue.point_code, issue.point_name,
                      issue.reporter, issue.reported_at, STATUS_LABELS[issue.status], issue.note, actor,
                      resolved_at, note, len(issue.photos), sum(len(e.photos) for e in issue.events), '開啟明細')
            row = index + 5
            for col, value in enumerate(values, 1):
                cell = _put(ws, row, col, value)
                cell.border = LINE
                if index % 2 == 0:
                    cell.fill = PALE
            status_cell = ws.cell(row, 8)
            status_cell.fill = PatternFill('solid', fgColor='FFF0D7' if issue.status == 'open' else 'E3F2E8')
            status_cell.font = Font(name='Microsoft JhengHei', size=11, bold=True,
                                    color='8C5608' if issue.status == 'open' else '286447')
            _link(ws.cell(row, 15), detail.title, f'A{detail_anchor}')
            # The full original notes remain in cells and in the expanded detail.
            lines = max(2, *(len(_wrapped_lines(value, max(10, width - 2)))
                            for value, width in zip(values, widths) if isinstance(value, str)))
            ws.row_dimensions[row].height = min(120, max(42, lines * 16))
        if not rows:
            _merged(ws, 6, 1, 15, '目前查詢條件沒有異常案件。')
            ws.row_dimensions[6].height = 28
            _merged(detail, 1, 1, 13, '目前查詢條件沒有異常案件。')
            detail.row_dimensions[1].height = 28
        detail.print_area = f'A1:M{max(1, detail_row - 1)}'
        ws.freeze_panes = 'E6'
        ws.auto_filter.ref = f'A5:O{max(5, len(rows) + 5)}'
        ws.print_title_rows = '1:5'
        ws.print_area = f'A1:O{max(6, len(rows) + 5)}'
        workbook.save(output)
        output.seek(0)
        return output
    except BaseException:
        output.close()
        raise
    finally:
        workbook.close()
        for stream in streams:
            stream.close()
