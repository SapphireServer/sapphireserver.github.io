class Jekyll::MarkdownHeader < Jekyll::Converters::Markdown
    def convert(content)
        super.gsub(/<h(\d) id="(.*?)">(.*?)<\/h(\d)>/, '<h\1 id="\2"><a class="anchor" href="#\2">\3</a> <span>§</span></h\1>')
    end
end