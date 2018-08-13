module ApplicationHelper

	# ページごとの完全なタイトルを返す
	def full_title(page_title = '')
		base_title = "Ruby on Rails Tutorial Sample App"
		if page_title.empty?
			base_title # 暗黙の戻り値
		else
			page_title + " | " + base_title
		end
	end
end
