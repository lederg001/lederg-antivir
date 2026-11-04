from src.antivir.ui import blend_hex, rounded_rectangle_points


def test_blend_hex_interpolates_red_to_green():
    assert blend_hex("#ff0000", "#00ff00", 0.0) == "#ff0000"
    assert blend_hex("#ff0000", "#00ff00", 1.0) == "#00ff00"
    assert blend_hex("#000000", "#ffffff", 0.5) == "#808080"


def test_rounded_rectangle_points_stay_inside_canvas_and_are_symmetric():
    points = rounded_rectangle_points(120, 44, radius=18, inset=1)
    xs = points[0::2]
    ys = points[1::2]

    assert len(points) >= 16
    assert min(xs) == 1
    assert max(xs) == 119
    assert min(ys) == 1
    assert max(ys) == 43
    assert len(xs) == len(ys)


def test_rounded_rectangle_radius_is_clamped_for_small_controls():
    points = rounded_rectangle_points(30, 20, radius=100, inset=0)

    assert min(points[0::2]) == 0
    assert max(points[0::2]) == 30
    assert min(points[1::2]) == 0
    assert max(points[1::2]) == 20


def test_pop_event_batch_limits_ui_work_and_preserves_remaining_events():
    from src.antivir.ui import pop_event_batch

    pending = list(range(7))
    first = pop_event_batch(pending, limit=3)

    assert first == [0, 1, 2]
    assert pending == [3, 4, 5, 6]
