import {
  Controller,
  Get,
  Injectable,
  ParseIntPipe,
  Query,
} from '@nestjs/common';
import { SearchesService } from './searches.service';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { SearchesDto } from './searches.dto/searches.dto';

@Controller('search')
@Injectable()
@ApiTags('Search')
export class SearchesController {
  constructor(private readonly searchesService: SearchesService) {}

  @Get()
  @ApiOperation({ summary: '키워드 검색, 카테고리, 지역, 위치인증 필터링' })
  async searchBy(
    @Query('page', ParseIntPipe) page: number,
    @Query() searchesDto: SearchesDto
  ) {
    const events = await this.searchesService.search(page, searchesDto);

    const event = events.map((item) => {
      const { GuestEvents, HostEvents, ...rest } = item;
      const hostUser = HostEvents[0]?.User?.UserDetail || null;

      return {
        event: rest,
        guestList: GuestEvents.length,
        hostUser: hostUser,
      };
    });
    return event;
  }
}
